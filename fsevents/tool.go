// gofsevents — macOS fseventsd parser for the DX_DFIR pipeline (docs/linux §4,
// the macOS matrix). Reads the DLS logs under a volume's `/.fseventsd/`
// directory — the gzip-compressed record of filesystem changes the kernel's
// fsevents writes — and emits one record per change: the path (relative to the
// volume root), the event id, the raw DLS flag word, and the file's node id.
//
// Rules (docs/linux §4.1): fseventsd carries no per-record wall-clock time —
// the event id is a monotonic counter, not a timestamp — so EventTime is left
// unset; the id gives ordering and the containing log's own mtime brackets the
// run. Flags is the raw DLS flag word: decoding its reason/type bits into names
// is byakugan's job (native verbatim, resolution is enrichment's). No user or
// volume is derived here.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOFSEVENTS_* environment. The argv flags are the
// debug pass-through:
//
//	gofsevents -f FILE | -d DIR [-q]
package fsevents

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Get-Sybers/gopinfo/batch"
	"github.com/Get-Sybers/gopinfo/discover"
	"github.com/Get-Sybers/gopinfo/record"
	"github.com/Get-Sybers/gopinfo/tstamp"
)

// fseventRecord is one DLS record (RecordType "fsevent").
type fseventRecord struct {
	record.Envelope
	Path    string `json:"Path"`
	EventID uint64 `json:"EventID"`
	Flags   uint32 `json:"Flags"`
	NodeID  uint64 `json:"NodeID,omitempty"`
}

// recLen is the fixed part of a record (after the NUL-terminated path) for each
// DLS page version: 1SLD = id(8)+flags(4); 2SLD adds node(8); 3SLD adds a
// further u32 this tool reads past but does not emit.
var recLen = map[string]int{"1SLD": 12, "2SLD": 20, "3SLD": 24}

// parseDLS reads an fseventsd DLS stream (already gunzipped by the caller):
// one or more pages, each a 4-byte magic ("1SLD"/"2SLD"/"3SLD"), a 4-byte
// unknown word and a 4-byte little-endian page size, then records until the
// page end. A record is a NUL-terminated path, an event id (u64 LE), flags
// (u32 LE) and, for 2SLD/3SLD, a node id (u64 LE). Empty-path records are page
// padding and are skipped. A page whose size overruns the buffer (a truncated
// log) is parsed to the end of what is present rather than failing the file.
func parseDLS(rd io.Reader, w *record.Writer) (int, error) {
	buf, err := io.ReadAll(rd)
	if err != nil {
		return 0, err
	}
	n := 0
	for off := 0; off+12 <= len(buf); {
		magic := string(buf[off : off+4])
		rl, ok := recLen[magic]
		if !ok {
			return n, fmt.Errorf("not a DLS page at offset %d (magic %q)", off, magic)
		}
		pageSize := int(binary.LittleEndian.Uint32(buf[off+8 : off+12]))
		end := off + pageSize
		if pageSize < 12 || end > len(buf) {
			end = len(buf)
		}
		for p := off + 12; p < end; {
			z := bytes.IndexByte(buf[p:end], 0)
			if z < 0 || p+z+1+rl > end {
				break
			}
			path := string(buf[p : p+z])
			p += z + 1
			rec := &fseventRecord{Path: path}
			rec.RecordType = "fsevent"
			rec.EventID = binary.LittleEndian.Uint64(buf[p : p+8])
			rec.Flags = binary.LittleEndian.Uint32(buf[p+8 : p+12])
			if magic != "1SLD" {
				rec.NodeID = binary.LittleEndian.Uint64(buf[p+12 : p+20])
			}
			p += rl
			if path == "" {
				continue // page padding / terminator
			}
			if err := w.Write(rec); err != nil {
				return n, err
			}
			n++
		}
		off = end
	}
	return n, nil
}

// isFseventsLog matches the gzip'd DLS logs under a `/.fseventsd/` directory,
// excluding the non-log markers the directory also holds (the volume-uuid file
// and the no_log sentinel).
func isFseventsLog(rel string) bool {
	rel = filepath.ToSlash(rel)
	if !strings.Contains(rel, ".fseventsd/") {
		return false
	}
	base := rel[strings.LastIndexByte(rel, '/')+1:]
	return base != "" && base != "fseventsd-uuid" && base != "no_log"
}

var Tool = batch.Tool{
	Name: "gofsevents",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			return isFseventsLog(rel)
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		f, err := discover.OpenAuto(item) // sniffs gzip by magic; the logs have no extension
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return parseDLS(f, w)
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one fseventsd DLS log")
		dir   = flag.String("d", "", "recurse a directory for fseventsd logs")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gofsevents                         (env-driven batch mode)\n"+
			"       gofsevents -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		f, err := discover.OpenAuto(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "gofsevents", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseDLS(f, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gofsevents: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return isFseventsLog(rel) })
		if err != nil {
			fmt.Fprintf(os.Stderr, "gofsevents: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "gofsevents: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
