// gotrash — XDG Trash parser for the DX_DFIR pipeline (docs/linux §4): the
// gorb of Linux. Finds every `*.trashinfo` under the input tree —
// `~/.local/share/Trash/info/` and per-volume `.Trash-<uid>/info/` — and
// emits one record per trashed file: the original path (percent-decoding per
// the XDG spec), the deletion time, and the paired `files/` twin's size when
// it is present in the tree.
//
// Rules (docs/linux §4.1): the deletion time is the artefact's own and lands
// in EventTime (TimeKind "deleted"); no user is derived from the path — the
// owning account is byakugan's fill-only-null inference over SourceFilename.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOTRASH_* environment. The argv flags are the
// debug pass-through:
//
//	gotrash -f FILE | -d DIR [-q]
package trash

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Get-Sybers/gopinfo/batch"
	"github.com/Get-Sybers/gopinfo/discover"
	"github.com/Get-Sybers/gopinfo/record"
	"github.com/Get-Sybers/gopinfo/tstamp"
)

// trashRecord is one .trashinfo file (RecordType "trashinfo").
type trashRecord struct {
	record.Envelope
	OriginalPath      string `json:"OriginalPath"`
	OriginalPathRaw   string `json:"OriginalPathRaw,omitempty"`
	DeletionDateRaw   string `json:"DeletionDateRaw,omitempty"`
	TrashedFileExists bool   `json:"TrashedFileExists"`
	TrashedSize       int64  `json:"TrashedSize,omitempty"`
}

// parseTrashinfo parses one [Trash Info] file. The paired content file is
// looked up at ../files/<name> relative to the info file when path != "".
func parseTrashinfo(rd io.Reader, infoPath string, loc *time.Location, w *record.Writer) (int, error) {
	rec := &trashRecord{}
	rec.RecordType = "trashinfo"
	sc := bufio.NewScanner(rd)
	seenHeader := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case line == "[Trash Info]":
			seenHeader = true
		case strings.HasPrefix(line, "Path="):
			rec.OriginalPathRaw = line[len("Path="):]
			if dec, err := url.PathUnescape(rec.OriginalPathRaw); err == nil {
				rec.OriginalPath = dec
			} else {
				rec.OriginalPath = rec.OriginalPathRaw
			}
			if rec.OriginalPath == rec.OriginalPathRaw {
				rec.OriginalPathRaw = "" // only keep the raw form when it differs
			}
		case strings.HasPrefix(line, "DeletionDate="):
			rec.DeletionDateRaw = line[len("DeletionDate="):]
			if t, ok := tstamp.FlexibleIn(rec.DeletionDateRaw, loc); ok {
				rec.EventTime = tstamp.ISO8601(t)
				rec.TimeKind = "deleted"
			}
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if !seenHeader || rec.OriginalPath == "" {
		return 0, fmt.Errorf("not a trashinfo file")
	}
	if infoPath != "" {
		name := strings.TrimSuffix(filepath.Base(infoPath), ".trashinfo")
		twin := filepath.Join(filepath.Dir(infoPath), "..", "files", name)
		if st, err := os.Stat(twin); err == nil {
			rec.TrashedFileExists = true
			if st.Mode().IsRegular() {
				rec.TrashedSize = st.Size()
			}
		}
	}
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

func isTrashinfo(rel string) bool {
	return strings.HasSuffix(strings.ToLower(rel), ".trashinfo")
}

var Tool = batch.Tool{
	Name: "gotrash",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			return isTrashinfo(rel)
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		f, err := os.Open(item)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return parseTrashinfo(f, item, cfg.Knowledge().Location(), w)
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one .trashinfo file")
		dir   = flag.String("d", "", "recurse a directory for .trashinfo files")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gotrash                            (env-driven batch mode)\n"+
			"       gotrash -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "gotrash", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseTrashinfo(f, path, nil, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gotrash: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return isTrashinfo(rel) })
		if err != nil {
			fmt.Fprintf(os.Stderr, "gotrash: %v\n", err)
			os.Exit(1)
		}
		for _, it := range items {
			rel, rerr := filepath.Rel(*dir, it)
			if rerr != nil {
				rel = it
			}
			one(it, filepath.ToSlash(rel))
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "gotrash: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
