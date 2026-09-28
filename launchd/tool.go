// golaunchd — macOS launchd job parser for the DX_DFIR pipeline: the Mac
// counterpart of gounit in the service stream (docs/linux §4). Finds the
// launchd property lists under every LaunchDaemons/ and LaunchAgents/
// directory in the input tree — /Library (third-party, system domain),
// /System/Library (Apple's, on a System volume), Users/<u>/Library (per
// user) — and the launchd override tables
// (private/var/db/com.apple.xpc.launchd/disabled*.plist), and emits one
// launchd_job record per job and one launchd_override per label.
//
// Rules (docs/linux §4.1): the job's keys are recorded verbatim — Program
// and ProgramArguments as given, KeepAlive and StartCalendarInterval
// rendered whole when they are dictionaries — and the domain and owner
// come from the file's location, a fact of the artefact, never an
// inference beyond it. Whether a job is persistence is byakugan's call.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOLAUNCHD_* environment. The argv flags are the
// debug pass-through:
//
//	golaunchd -f FILE | -d DIR [-q]
package launchd

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/get-sybers/gopinfo/batch"
	"github.com/get-sybers/gopinfo/discover"
	"github.com/get-sybers/gopinfo/plist"
	"github.com/get-sybers/gopinfo/record"
	"github.com/get-sybers/gopinfo/tstamp"
)

// jobRecord is one launchd job (RecordType launchd_job) or one override
// row (launchd_override).
type jobRecord struct {
	record.Envelope
	Label  string `json:"Label"`
	Kind   string `json:"Kind,omitempty"`   // daemon | agent
	Domain string `json:"Domain,omitempty"` // system (/System/Library) | library (/Library) | user (a user's Library)
	Owner  string `json:"Owner,omitempty"`  // the user whose Library holds the job
	// the job
	Program                     string            `json:"Program,omitempty"`
	ProgramArguments            []string          `json:"ProgramArguments,omitempty"`
	RunAtLoad                   *bool             `json:"RunAtLoad,omitempty"`
	KeepAlive                   string            `json:"KeepAlive,omitempty"`
	Disabled                    *bool             `json:"Disabled,omitempty"`
	LaunchOnlyOnce              *bool             `json:"LaunchOnlyOnce,omitempty"`
	StartInterval               *int64            `json:"StartInterval,omitempty"`
	StartCalendarInterval       []string          `json:"StartCalendarInterval,omitempty"`
	StartOnMount                *bool             `json:"StartOnMount,omitempty"`
	WatchPaths                  []string          `json:"WatchPaths,omitempty"`
	QueueDirectories            []string          `json:"QueueDirectories,omitempty"`
	UserName                    string            `json:"UserName,omitempty"`
	GroupName                   string            `json:"GroupName,omitempty"`
	WorkingDirectory            string            `json:"WorkingDirectory,omitempty"`
	RootDirectory               string            `json:"RootDirectory,omitempty"`
	EnvironmentVariables        map[string]string `json:"EnvironmentVariables,omitempty"`
	StandardInPath              string            `json:"StandardInPath,omitempty"`
	StandardOutPath             string            `json:"StandardOutPath,omitempty"`
	StandardErrorPath           string            `json:"StandardErrorPath,omitempty"`
	MachServices                []string          `json:"MachServices,omitempty"`
	Sockets                     []string          `json:"Sockets,omitempty"`
	ProcessType                 string            `json:"ProcessType,omitempty"`
	LimitLoadToSessionType      []string          `json:"LimitLoadToSessionType,omitempty"`
	AssociatedBundleIdentifiers []string          `json:"AssociatedBundleIdentifiers,omitempty"`
	Nice                        *int64            `json:"Nice,omitempty"`
	Keys                        []string          `json:"Keys,omitempty"`
	LinkTarget                  string            `json:"LinkTarget,omitempty"` // the file is a symlink: where the job's plist really lives
	// the override
	OverrideUID *int64 `json:"OverrideUID,omitempty"`
}

// ---- classification --------------------------------------------------------

var disabledRe = regexp.MustCompile(`^disabled(?:\.(\d+))?\.plist$`)

// classify maps a rel path to its family: "job" for a .plist under a
// LaunchDaemons/ or LaunchAgents/ directory, "override" for launchd's
// disabled*.plist tables, "" otherwise.
func classify(rel string) string {
	rel = strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(rel)
	if !strings.HasSuffix(base, ".plist") {
		return ""
	}
	dir := filepath.Base(filepath.Dir(rel))
	switch dir {
	case "launchdaemons", "launchagents":
		return "job"
	case "com.apple.xpc.launchd":
		if disabledRe.MatchString(base) {
			return "override"
		}
	}
	return ""
}

// location derives the kind, domain and owner from the file's path.
func location(rel string) (kind, domain, owner string) {
	slash := filepath.ToSlash(rel)
	lower := strings.ToLower(slash)
	dir := filepath.Base(filepath.Dir(lower))
	if dir == "launchdaemons" {
		kind = "daemon"
	} else {
		kind = "agent"
	}
	comps := strings.Split(strings.Trim(slash, "/"), "/")
	for i, c := range comps {
		lc := strings.ToLower(c)
		switch {
		case lc == "system" && i+1 < len(comps) && strings.EqualFold(comps[i+1], "library"):
			return kind, "system", ""
		case lc == "library" && i == 0:
			return kind, "library", ""
		case lc == "users" && i+2 < len(comps) && strings.EqualFold(comps[i+2], "library"):
			return kind, "user", comps[i+1]
		case lc == "root" && i > 0 && strings.EqualFold(comps[i-1], "var") && i+1 < len(comps) && strings.EqualFold(comps[i+1], "library"):
			return kind, "user", "root"
		}
	}
	// a Library/ not at the root of the staged tree (a partial stage) is
	// the library domain; anything else stays unclassified
	if strings.Contains(lower, "/library/launch") || strings.HasPrefix(lower, "library/launch") {
		return kind, "library", ""
	}
	return kind, "", ""
}

// ---- parsers ---------------------------------------------------------------

func load(rd io.Reader) (map[string]any, error) {
	b, err := io.ReadAll(io.LimitReader(rd, plist.MaxSize+1))
	if err != nil {
		return nil, err
	}
	v, err := plist.Decode(b)
	if err != nil {
		return nil, err
	}
	d := plist.Dict(v)
	if d == nil {
		return nil, fmt.Errorf("not a dictionary property list")
	}
	return d, nil
}

func boolPtr(v any) *bool {
	if b, ok := plist.Bool(v); ok {
		return &b
	}
	return nil
}

func intPtr(v any) *int64 {
	if n, ok := plist.Int(v); ok {
		return &n
	}
	return nil
}

func dictKeys(v any) []string {
	d := plist.Dict(v)
	if d == nil {
		return nil
	}
	out := make([]string, 0, len(d))
	for k := range d {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// calendar renders StartCalendarInterval — one dict or an array of them —
// as "Minute=0 Hour=3" strings, the keys in launchd's own order.
func calendar(v any) []string {
	var out []string
	for _, e := range plist.Array(v) {
		d := plist.Dict(e)
		if d == nil {
			out = append(out, plist.Render(e))
			continue
		}
		var parts []string
		for _, k := range []string{"Minute", "Hour", "Day", "Weekday", "Month"} {
			if x, ok := d[k]; ok {
				parts = append(parts, k+"="+plist.Render(x))
			}
		}
		for _, k := range dictKeys(d) {
			switch k {
			case "Minute", "Hour", "Day", "Weekday", "Month":
			default:
				parts = append(parts, k+"="+plist.Render(d[k]))
			}
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

// linkText reports a staged symlink: its content is the target path (a
// single line, no NUL, with a separator) rather than a property list.
// Apple's System volume links several LaunchAgents into the cryptex
// (../../../Library/Apple/System/Library/LaunchAgents/…).
func linkText(b []byte) (string, bool) {
	s := strings.TrimRight(string(b), "\n")
	if len(b) == 0 || len(b) > 1024 || !strings.Contains(s, "/") || strings.ContainsAny(s, "\x00\n<") {
		return "", false
	}
	return s, true
}

// parseJob emits one launchd_job row.
func parseJob(rd io.Reader, rel string, w *record.Writer) (int, error) {
	b, err := io.ReadAll(io.LimitReader(rd, plist.MaxSize+1))
	if err != nil {
		return 0, err
	}
	if target, ok := linkText(b); ok && !plist.IsBinary(b) {
		// the job's definition sits at the target: recorded as a link,
		// labelled by the file's name, so the agent is not lost
		rec := &jobRecord{Label: strings.TrimSuffix(filepath.Base(rel), ".plist"), LinkTarget: target}
		rec.RecordType = "launchd_job"
		rec.Kind, rec.Domain, rec.Owner = location(rel)
		if err := w.Write(rec); err != nil {
			return 0, err
		}
		return 1, nil
	}
	d, err := load(bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	// every dictionary plist in a Launch* directory is a job as far as
	// launchd is concerned — an EMPTY one (<dict/>, seen left behind by
	// Google's Keystone) is recorded too, its label the file's name and
	// Keys empty, rather than hidden as a failure
	rec := &jobRecord{Label: plist.String(d["Label"])}
	rec.RecordType = "launchd_job"
	if rec.Label == "" {
		rec.Label = strings.TrimSuffix(filepath.Base(rel), ".plist")
	}
	rec.Kind, rec.Domain, rec.Owner = location(rel)
	rec.Program = plist.String(d["Program"])
	rec.ProgramArguments = plist.Strings(d["ProgramArguments"])
	rec.RunAtLoad = boolPtr(d["RunAtLoad"])
	if v, ok := d["KeepAlive"]; ok {
		rec.KeepAlive = plist.Render(v)
	}
	rec.Disabled = boolPtr(d["Disabled"])
	rec.LaunchOnlyOnce = boolPtr(d["LaunchOnlyOnce"])
	rec.StartInterval = intPtr(d["StartInterval"])
	rec.StartCalendarInterval = calendar(d["StartCalendarInterval"])
	rec.StartOnMount = boolPtr(d["StartOnMount"])
	rec.WatchPaths = plist.Strings(d["WatchPaths"])
	rec.QueueDirectories = plist.Strings(d["QueueDirectories"])
	rec.UserName = plist.String(d["UserName"])
	rec.GroupName = plist.String(d["GroupName"])
	rec.WorkingDirectory = plist.String(d["WorkingDirectory"])
	rec.RootDirectory = plist.String(d["RootDirectory"])
	if env := plist.Dict(d["EnvironmentVariables"]); len(env) > 0 {
		rec.EnvironmentVariables = map[string]string{}
		for k, v := range env {
			rec.EnvironmentVariables[k] = plist.Render(v)
		}
	}
	rec.StandardInPath = plist.String(d["StandardInPath"])
	rec.StandardOutPath = plist.String(d["StandardOutPath"])
	rec.StandardErrorPath = plist.String(d["StandardErrorPath"])
	rec.MachServices = dictKeys(d["MachServices"])
	rec.Sockets = dictKeys(d["Sockets"])
	rec.ProcessType = plist.String(d["ProcessType"])
	rec.LimitLoadToSessionType = plist.Strings(d["LimitLoadToSessionType"])
	rec.AssociatedBundleIdentifiers = plist.Strings(d["AssociatedBundleIdentifiers"])
	rec.Nice = intPtr(d["Nice"])
	rec.Keys = dictKeys(d)
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

// parseOverrides emits one launchd_override row per label of a
// disabled[.<uid>].plist: Disabled true/false as launchd recorded it.
func parseOverrides(rd io.Reader, rel string, w *record.Writer) (int, error) {
	d, err := load(rd)
	if err != nil {
		return 0, err
	}
	var uid *int64
	if m := disabledRe.FindStringSubmatch(strings.ToLower(filepath.Base(rel))); m != nil && m[1] != "" {
		if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			uid = &n
		}
	}
	labels := dictKeys(d)
	n := 0
	for _, label := range labels {
		rec := &jobRecord{Label: label, OverrideUID: uid}
		rec.RecordType = "launchd_override"
		rec.Disabled = boolPtr(d[label])
		if err := w.Write(rec); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func parseByFamily(rd io.Reader, family, rel string, w *record.Writer) (int, error) {
	switch family {
	case "job":
		return parseJob(rd, rel, w)
	case "override":
		return parseOverrides(rd, rel, w)
	}
	return 0, fmt.Errorf("unknown family %q", family)
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "golaunchd",
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
		return parseByFamily(f, classify(rel), rel, w)
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one launchd plist (kind and domain from its path)")
		dir   = flag.String("d", "", "recurse a directory")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: golaunchd                          (env-driven batch mode)\n"+
			"       golaunchd -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		family := classify(rel)
		if family == "" {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "golaunchd: %s: not a launchd file, skipped\n", path)
			}
			return
		}
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "golaunchd", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseByFamily(f, family, rel, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "golaunchd: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return classify(rel) != "" })
		if err != nil {
			fmt.Fprintf(os.Stderr, "golaunchd: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "golaunchd: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
