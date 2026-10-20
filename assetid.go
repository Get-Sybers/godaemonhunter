package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Get-Sybers/gopinfo/record"
)

// assetID resolves the evidence-asset identity that names an item's flat output
// file. The strongest durable identifier the gomount stage manifest carries for
// the image wins, else the caller's fallback (a loose tree, a live host, a raw
// image with no serial):
//
//	disk_serial  →  volume_guid  →  image_sha256  →  fallback
//
// Equal ids across acquisitions of one asset are the point: two images of one
// disk resolve to the same id, so their records merge into one file rather than
// overwrite. The result is sanitised to a single safe path component.
func assetID(root, fallback string) string {
	if id := manifestAssetID(root); id != "" {
		return sanitizeName(id)
	}
	return sanitizeName(fallback)
}

// manifestAssetID reads the image-scoped identity off <root>/materialise.jsonl.
// The manifest's path-less metadata row carries the Origin field contract's
// image keys (disk_serial/volume_guid/image_sha256); a row WITH a path is a
// per-file origin and is skipped. "" when the manifest is absent (loose
// evidence) or carries none of the keys — the caller then uses its fallback.
func manifestAssetID(root string) string {
	if root == "" {
		return ""
	}
	f, err := os.Open(filepath.Join(root, record.ManifestName))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	var serial, guid, sha string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var raw map[string]any
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		if p, _ := raw["path"].(string); strings.TrimSpace(p) != "" {
			continue // a per-file origin row, not the image-scoped metadata row
		}
		if serial == "" {
			serial = manifestStr(raw, "disk_serial")
		}
		if guid == "" {
			guid = manifestStr(raw, "volume_guid")
		}
		if sha == "" {
			sha = manifestStr(raw, "image_sha256")
		}
	}
	switch {
	case serial != "":
		return serial
	case guid != "":
		return guid
	default:
		return sha
	}
}

func manifestStr(raw map[string]any, k string) string {
	if v, ok := raw[k].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// sanitizeName reduces an asset id to one filesystem-safe path component: the
// volume GUID's braces, a serial's spaces and any separator collapse to '_',
// and the dots of an image item name (disk.E01) are kept so the fallback reads
// naturally. An empty or fully-stripped id yields "unknown" so a run never
// writes to a bare ".jsonl".
func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "._")
	if out == "" {
		return "unknown"
	}
	return out
}
