package main

import (
	"os"
	"path/filepath"
	"testing"
)

func stageManifest(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "materialise.jsonl"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAssetIDLadder(t *testing.T) {
	// the strongest id on the metadata row wins; a per-file row is ignored.
	d := t.TempDir()
	stageManifest(t, d, `{"path":"","disk_serial":"WD-WX11A","volume_guid":"VG","image_sha256":"SHA"}
{"path":"/x","disk_serial":"per-file-ignored"}
`)
	if got := assetID(d, "fallback"); got != "WD-WX11A" {
		t.Errorf("disk_serial rung: got %q, want WD-WX11A", got)
	}

	// no serial → volume_guid, sanitised (braces stripped)
	d2 := t.TempDir()
	stageManifest(t, d2, `{"path":"","volume_guid":"{VOL-GUID-02}","image_sha256":"abc"}`+"\n")
	if got := assetID(d2, "fallback"); got != "VOL-GUID-02" {
		t.Errorf("volume_guid rung: got %q, want VOL-GUID-02", got)
	}

	// no serial or guid → image_sha256
	d3 := t.TempDir()
	stageManifest(t, d3, `{"path":"","image_sha256":"a1b2c3d4"}`+"\n")
	if got := assetID(d3, "fallback"); got != "a1b2c3d4" {
		t.Errorf("image_sha256 rung: got %q, want a1b2c3d4", got)
	}
}

func TestAssetIDFallback(t *testing.T) {
	// a manifest with no identity keys → fallback
	d := t.TempDir()
	stageManifest(t, d, `{"path":"","image":"disk.vmdk"}`+"\n")
	if got := assetID(d, "disk.vmdk"); got != "disk.vmdk" {
		t.Errorf("no-id manifest: got %q, want disk.vmdk", got)
	}
	// absent manifest (loose evidence) → fallback
	if got := assetID(t.TempDir(), "host-01"); got != "host-01" {
		t.Errorf("absent manifest: got %q, want host-01", got)
	}
	// empty root is safe
	if got := assetID("", "host-01"); got != "host-01" {
		t.Errorf("empty root: got %q, want host-01", got)
	}
}

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"WD-WX11A":        "WD-WX11A",
		"disk.E01":        "disk.E01", // the image-item fallback keeps its dots
		`a b\c/d`:         "a_b_c_d",
		"{11111111-2222}": "11111111-2222",
		"  spaced  ":      "spaced",
		"":                "unknown",
		"...":             "unknown",
	} {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}
