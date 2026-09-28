// gounit — systemd unit parser for the DX_DFIR pipeline (docs/linux §4):
// the Services/Run-keys surface of Linux. Finds unit files (.service,
// .timer, .socket, .mount, .automount, .path, .target, .slice, .swap) and
// their drop-in fragments (<unit>.d/*.conf) across etc/, run/, usr/lib|lib/
// and per-user systemd directories, and emits one record per unit file with
// the persistence-relevant directives.
//
// Rules (docs/linux §4.1): directives are recorded verbatim (every Exec*
// line in order, the raw OnCalendar spec — next-run resolution is
// derivation and byakugan's); Scope records WHERE the file sat (vendor vs
// admin vs runtime vs user), which is location fact, not judgement.
// Enablement symlinks (*.wants/) are filesystem structure — the access
// layer's timeline records them; this parser reads only regular files.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOUNIT_* environment. The argv flags are the
// debug pass-through:
//
//	gounit -f FILE | -d DIR [-q]
package unit

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

// unitRecord is one unit file or drop-in fragment (RecordType
// "systemd_unit" / "systemd_dropin").
type unitRecord struct {
	record.Envelope
	Unit            string   `json:"Unit"`
	UnitType        string   `json:"UnitType"`
	Scope           string   `json:"Scope,omitempty"`
	DropIn          bool     `json:"DropIn,omitempty"`
	Description     string   `json:"Description,omitempty"`
	ExecStart       []string `json:"ExecStart,omitempty"`
	ExecStartPre    []string `json:"ExecStartPre,omitempty"`
	ExecStartPost   []string `json:"ExecStartPost,omitempty"`
	ExecStop        []string `json:"ExecStop,omitempty"`
	ExecStopPost    []string `json:"ExecStopPost,omitempty"`
	ExecReload      []string `json:"ExecReload,omitempty"`
	ExecCondition   []string `json:"ExecCondition,omitempty"`
	ServiceType     string   `json:"ServiceType,omitempty"`
	User            string   `json:"User,omitempty"`
	Group           string   `json:"Group,omitempty"`
	Environment     []string `json:"Environment,omitempty"`
	EnvironmentFile []string `json:"EnvironmentFile,omitempty"`
	WorkingDir      string   `json:"WorkingDirectory,omitempty"`
	OnCalendar      []string `json:"OnCalendar,omitempty"`
	OnBootSec       string   `json:"OnBootSec,omitempty"`
	OnStartupSec    string   `json:"OnStartupSec,omitempty"`
	OnUnitActiveSec string   `json:"OnUnitActiveSec,omitempty"`
	Persistent      string   `json:"Persistent,omitempty"`
	Unit_           string   `json:"TimerUnit,omitempty"` // a timer's [Timer] Unit=
	ListenStream    []string `json:"ListenStream,omitempty"`
	What            string   `json:"What,omitempty"`
	Where           string   `json:"Where,omitempty"`
	MountType       string   `json:"MountType,omitempty"`
	MountOptions    string   `json:"MountOptions,omitempty"`
	WantedBy        []string `json:"WantedBy,omitempty"`
	RequiredBy      []string `json:"RequiredBy,omitempty"`
	Also            []string `json:"Also,omitempty"`
	Alias           []string `json:"Alias,omitempty"`
	Requires        []string `json:"Requires,omitempty"`
	Wants           []string `json:"Wants,omitempty"`
	After           []string `json:"After,omitempty"`
	Before          []string `json:"Before,omitempty"`
	ConditionLines  []string `json:"ConditionLines,omitempty"`
}

// ---- classification --------------------------------------------------------

var unitSuffixes = []string{
	".service", ".timer", ".socket", ".mount", ".automount", ".path",
	".target", ".slice", ".swap",
}

// classify returns (unit name, unit type, drop-in) for a rel path, or
// ("","",false) when the file is not a unit. A drop-in is <unit>.d/*.conf.
func classify(rel string) (unit, utype string, dropin bool) {
	base := filepath.Base(rel)
	dir := filepath.Base(filepath.Dir(rel))
	lower := strings.ToLower(base)
	for _, s := range unitSuffixes {
		if strings.HasSuffix(lower, s) {
			return base, strings.TrimPrefix(s, "."), false
		}
		if strings.HasSuffix(strings.ToLower(dir), s+".d") && strings.HasSuffix(lower, ".conf") {
			return strings.TrimSuffix(dir, ".d"), strings.TrimPrefix(s, "."), true
		}
	}
	return "", "", false
}

// scope names where in the tree the unit sat: vendor (usr/lib, lib),
// admin (etc), runtime (run), user (~/.config or user dirs), other.
func scope(rel string) string {
	p := "/" + strings.ToLower(filepath.ToSlash(rel))
	switch {
	case strings.Contains(p, "/usr/lib/systemd/") || strings.Contains(p, "/lib/systemd/"):
		return "vendor"
	case strings.Contains(p, "/etc/systemd/"):
		return "admin"
	case strings.Contains(p, "/run/systemd/"):
		return "runtime"
	case strings.Contains(p, "/.config/systemd/") || strings.Contains(p, "/systemd/user/"):
		return "user"
	}
	return "other"
}

// ---- parsing ---------------------------------------------------------------

// parseUnit parses one unit file into one record. systemd syntax: [Section]
// headers, Key=Value, '#'/';' comments, trailing-backslash continuations,
// repeated keys accumulate (an empty Exec*= reset clears the list).
func parseUnit(rd io.Reader, rec *unitRecord, w *record.Writer) (int, error) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	section, pending := "", ""
	sawSection := false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if pending != "" {
			line = pending + " " + strings.TrimSpace(line)
			pending = ""
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasSuffix(trimmed, "\\") {
			pending = strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(trimmed[1 : len(trimmed)-1])
			sawSection = true
			continue
		}
		k, v, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		rec.apply(section, k, v)
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if !sawSection {
		return 0, fmt.Errorf("no [Section] headers: not a systemd unit file")
	}
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

// addOrReset implements systemd list semantics: an empty assignment resets.
func addOrReset(dst *[]string, v string) {
	if v == "" {
		*dst = nil
		return
	}
	*dst = append(*dst, v)
}

func splitWords(dst *[]string, v string) {
	if v == "" {
		*dst = nil
		return
	}
	*dst = append(*dst, strings.Fields(v)...)
}

func (r *unitRecord) apply(section, k, v string) {
	lk := strings.ToLower(k)
	switch section {
	case "unit":
		switch lk {
		case "description":
			r.Description = v
		case "requires":
			splitWords(&r.Requires, v)
		case "wants":
			splitWords(&r.Wants, v)
		case "after":
			splitWords(&r.After, v)
		case "before":
			splitWords(&r.Before, v)
		default:
			if strings.HasPrefix(lk, "condition") || strings.HasPrefix(lk, "assert") {
				r.ConditionLines = append(r.ConditionLines, k+"="+v)
			}
		}
	case "service", "mount", "swap":
		switch lk {
		case "what":
			r.What = v
		case "where":
			r.Where = v
		case "options":
			r.MountOptions = v
		case "execstart":
			addOrReset(&r.ExecStart, v)
		case "execstartpre":
			addOrReset(&r.ExecStartPre, v)
		case "execstartpost":
			addOrReset(&r.ExecStartPost, v)
		case "execstop":
			addOrReset(&r.ExecStop, v)
		case "execstoppost":
			addOrReset(&r.ExecStopPost, v)
		case "execreload":
			addOrReset(&r.ExecReload, v)
		case "execcondition":
			addOrReset(&r.ExecCondition, v)
		case "type":
			if section == "service" {
				r.ServiceType = v
			} else {
				r.MountType = v
			}
		case "user":
			r.User = v
		case "group":
			r.Group = v
		case "environment":
			addOrReset(&r.Environment, v)
		case "environmentfile":
			addOrReset(&r.EnvironmentFile, v)
		case "workingdirectory":
			r.WorkingDir = v
		}
	case "timer":
		switch lk {
		case "oncalendar":
			addOrReset(&r.OnCalendar, v)
		case "onbootsec":
			r.OnBootSec = v
		case "onstartupsec":
			r.OnStartupSec = v
		case "onunitactivesec":
			r.OnUnitActiveSec = v
		case "persistent":
			r.Persistent = v
		case "unit":
			r.Unit_ = v
		}
	case "socket":
		if lk == "listenstream" {
			addOrReset(&r.ListenStream, v)
		}
	case "install":
		switch lk {
		case "wantedby":
			splitWords(&r.WantedBy, v)
		case "requiredby":
			splitWords(&r.RequiredBy, v)
		case "also":
			splitWords(&r.Also, v)
		case "alias":
			splitWords(&r.Alias, v)
		}
	}
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "gounit",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			u, _, _ := classify(rel)
			return u != ""
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		rel, _ := filepath.Rel(cfg.InputDir, item)
		rel = filepath.ToSlash(rel)
		unit, utype, dropin := classify(rel)
		rec := &unitRecord{Unit: unit, UnitType: utype, DropIn: dropin, Scope: scope(rel)}
		rec.RecordType = "systemd_unit"
		if dropin {
			rec.RecordType = "systemd_dropin"
		}
		f, err := os.Open(item)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return parseUnit(f, rec, w)
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one unit file")
		dir   = flag.String("d", "", "recurse a directory for unit files")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gounit                             (env-driven batch mode)\n"+
			"       gounit -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		unit, utype, dropin := classify(rel)
		if unit == "" {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gounit: %s: not a unit file, skipped\n", path)
			}
			return
		}
		rec := &unitRecord{Unit: unit, UnitType: utype, DropIn: dropin, Scope: scope(rel)}
		rec.RecordType = "systemd_unit"
		if dropin {
			rec.RecordType = "systemd_dropin"
		}
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "gounit", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseUnit(f, rec, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gounit: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool {
			u, _, _ := classify(rel)
			return u != ""
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "gounit: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "gounit: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
