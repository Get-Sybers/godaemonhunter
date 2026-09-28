// goctl — kernel and loader control-surface parser for the DX_DFIR
// pipeline (docs/linux §4): the persisted knobs that change how the kernel
// and the dynamic loader behave, and therefore a classic persistence and
// anti-forensics surface. sysctl parameters (sysctl.conf + sysctl.d),
// kernel module policy (modules-load.d, etc/modules, modprobe.d — the
// `install`/`remove` lines carry shell commands, `blacklist` hides
// modules), and the dynamic loader controls (ld.so.preload — THE preload
// persistence artefact — and ld.so.conf with its drop-ins).
//
// Rules (docs/linux §4.1): extraction only, values verbatim; Scope records
// WHERE the file sat (vendor/admin/runtime), the location fact that makes
// an /etc override stand out. Judging a parameter or a preload entry is
// byakugan's.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOCTL_* environment. The argv flags are the
// debug pass-through:
//
//	goctl -f FILE | -d DIR [-q]
package ctl

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/get-sybers/gopinfo/batch"
	"github.com/get-sybers/gopinfo/discover"
	"github.com/get-sybers/gopinfo/record"
	"github.com/get-sybers/gopinfo/tstamp"
)

// ctlRecord is the one record shape; RecordType says which family a row is.
type ctlRecord struct {
	record.Envelope
	Scope     string `json:"Scope,omitempty"`
	Parameter string `json:"Parameter,omitempty"`
	Value     string `json:"Value,omitempty"`
	Module    string `json:"Module,omitempty"`
	Directive string `json:"Directive,omitempty"`
	Library   string `json:"Library,omitempty"`
	Path      string `json:"Path,omitempty"`
	Include   string `json:"Include,omitempty"`
	Line      int    `json:"Line,omitempty"`
	Raw       string `json:"Raw,omitempty"`
}

// ---- classification --------------------------------------------------------

func classify(rel string) string {
	rel = strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(rel)
	dir := filepath.Base(filepath.Dir(rel))
	switch base {
	case "sysctl.conf":
		return "sysctl"
	case "modules":
		if dir == "etc" {
			return "modules_load"
		}
	case "ld.so.preload":
		return "ld_preload"
	case "ld.so.conf":
		return "ld_conf"
	}
	if strings.HasSuffix(base, ".conf") {
		switch dir {
		case "sysctl.d":
			return "sysctl"
		case "modules-load.d":
			return "modules_load"
		case "modprobe.d":
			return "modprobe"
		case "ld.so.conf.d":
			return "ld_conf"
		}
	}
	return ""
}

// scope names where in the tree the file sat: vendor (usr/lib, lib),
// admin (etc), runtime (run), other.
func scope(rel string) string {
	p := "/" + strings.ToLower(filepath.ToSlash(rel))
	switch {
	case strings.Contains(p, "/usr/lib/") || strings.Contains(p, "/lib/"):
		return "vendor"
	case strings.Contains(p, "/etc/"):
		return "admin"
	case strings.Contains(p, "/run/"):
		return "runtime"
	}
	return "other"
}

// ---- parsers ---------------------------------------------------------------

func lineScanner(rd io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return sc
}

// eachLine drives a per-line parser with comment/blank skipping.
func eachLine(rd io.Reader, w *record.Writer, fn func(lineNo int, line string) *ctlRecord) (int, error) {
	sc := lineScanner(rd)
	emitted, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		rec := fn(lineNo, line)
		if rec == nil {
			continue
		}
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

// parseSysctl: one sysctl_param per `key = value` (or key=value) line.
func parseSysctl(rd io.Reader, sc string, w *record.Writer) (int, error) {
	return eachLine(rd, w, func(n int, line string) *ctlRecord {
		// a leading '-' means "ignore errors" — strip it, keep the fact in Raw
		trimmed := strings.TrimPrefix(line, "-")
		k, v, ok := strings.Cut(trimmed, "=")
		rec := &ctlRecord{Line: n, Scope: sc, Raw: line}
		rec.RecordType = "sysctl_param"
		if ok {
			rec.Parameter = strings.TrimSpace(k)
			rec.Value = strings.TrimSpace(v)
		}
		return rec
	})
}

// parseModulesLoad: one module_load per module name line.
func parseModulesLoad(rd io.Reader, sc string, w *record.Writer) (int, error) {
	return eachLine(rd, w, func(n int, line string) *ctlRecord {
		rec := &ctlRecord{Line: n, Scope: sc}
		rec.RecordType = "module_load"
		f := strings.Fields(line)
		rec.Module = f[0]
		if len(f) > 1 {
			rec.Raw = line // module parameters on the etc/modules form
		}
		return rec
	})
}

// modprobe directives; install/remove carry shell commands — the classic
// module-hijack persistence — so Value holds them verbatim.
var modprobeDirectives = map[string]bool{
	"alias": true, "options": true, "install": true, "remove": true,
	"blacklist": true, "softdep": true, "blacklist_module": true,
}

// parseModprobe: one modprobe_directive per line.
func parseModprobe(rd io.Reader, sc string, w *record.Writer) (int, error) {
	return eachLine(rd, w, func(n int, line string) *ctlRecord {
		f := strings.Fields(line)
		rec := &ctlRecord{Line: n, Scope: sc, Raw: line}
		rec.RecordType = "modprobe_directive"
		if modprobeDirectives[strings.ToLower(f[0])] {
			rec.Directive = strings.ToLower(f[0])
			if len(f) > 1 {
				rec.Module = f[1]
			}
			if len(f) > 2 {
				rec.Value = strings.Join(f[2:], " ")
			}
		}
		return rec
	})
}

// parseLdPreload: one ld_preload per library entry (whitespace- or
// colon-separated, per the loader's own rules).
func parseLdPreload(rd io.Reader, sc string, w *record.Writer) (int, error) {
	emitted := 0
	scanner := lineScanner(rd)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(scanner.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, lib := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ':'
		}) {
			rec := &ctlRecord{Line: lineNo, Scope: sc, Library: lib}
			rec.RecordType = "ld_preload"
			if err := w.Write(rec); err != nil {
				return emitted, err
			}
			emitted++
		}
	}
	return emitted, scanner.Err()
}

// parseLdConf: one ld_path per path line; include directives kept.
func parseLdConf(rd io.Reader, sc string, w *record.Writer) (int, error) {
	return eachLine(rd, w, func(n int, line string) *ctlRecord {
		rec := &ctlRecord{Line: n, Scope: sc}
		rec.RecordType = "ld_path"
		if v, ok := strings.CutPrefix(line, "include "); ok {
			rec.Include = strings.TrimSpace(v)
		} else {
			rec.Path = line
		}
		return rec
	})
}

func parseByFamily(rd io.Reader, family, sc string, w *record.Writer) (int, error) {
	switch family {
	case "sysctl":
		return parseSysctl(rd, sc, w)
	case "modules_load":
		return parseModulesLoad(rd, sc, w)
	case "modprobe":
		return parseModprobe(rd, sc, w)
	case "ld_preload":
		return parseLdPreload(rd, sc, w)
	case "ld_conf":
		return parseLdConf(rd, sc, w)
	}
	return 0, fmt.Errorf("unknown family %q", family)
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "goctl",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			return classify(rel) != ""
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		rel, _ := filepath.Rel(cfg.InputDir, item)
		rel = filepath.ToSlash(rel)
		f, err := os.Open(item)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return parseByFamily(f, classify(rel), scope(rel), w)
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one control file (family from its path)")
		dir   = flag.String("d", "", "recurse a directory")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: goctl                              (env-driven batch mode)\n"+
			"       goctl -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		family := classify(rel)
		if family == "" {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "goctl: %s: not a goctl file, skipped\n", path)
			}
			return
		}
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "goctl", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseByFamily(f, family, scope(rel), w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "goctl: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return classify(rel) != "" })
		if err != nil {
			fmt.Fprintf(os.Stderr, "goctl: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "goctl: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
