// gomachost — macOS host identity parser for the DX_DFIR pipeline: the
// Mac counterpart of gohost in Layer 1 (docs/linux §4). Extracts who the
// imaged Mac is from the property lists that carry it — the OS version
// (SystemVersion.plist), the host's names and hardware model
// (SystemConfiguration/preferences.plist), the system time zone and
// locale (the system .GlobalPreferences.plist) — and emits the SAME record
// types gohost does (os_release, hostname, timezone, locale), so the
// knowledge store loads a Mac exactly as it loads a Linux host and every
// Layer-2 record carries the Host block.
//
// Rules (docs/linux §4.1): extraction only — the time zone is handed over
// as the name the host had selected; applying it to naive timestamps is
// byakugan's.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOMACHOST_* environment. The argv flags are the
// debug pass-through:
//
//	gomachost -f FILE | -d DIR [-q]
package machost

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/get-sybers/gopinfo/batch"
	"github.com/get-sybers/gopinfo/discover"
	"github.com/get-sybers/gopinfo/plist"
	"github.com/get-sybers/gopinfo/record"
	"github.com/get-sybers/gopinfo/tstamp"
)

// hostRecord is the one record shape; RecordType says which family a row
// is. The field names match gohost's so the knowledge store reads both.
type hostRecord struct {
	record.Envelope
	// os_release
	Name       string            `json:"Name,omitempty"`
	ID         string            `json:"ID,omitempty"`
	VersionID  string            `json:"VersionID,omitempty"`
	PrettyName string            `json:"PrettyName,omitempty"`
	Fields     map[string]string `json:"Fields,omitempty"`
	// hostname
	Hostname      string `json:"Hostname,omitempty"`
	ComputerName  string `json:"ComputerName,omitempty"`
	LocalHostName string `json:"LocalHostName,omitempty"`
	Model         string `json:"Model,omitempty"`
	// timezone
	Timezone string `json:"Timezone,omitempty"`
	City     string `json:"City,omitempty"`
	// locale
	Lang      string   `json:"Lang,omitempty"`
	Country   string   `json:"Country,omitempty"`
	Languages []string `json:"Languages,omitempty"`
}

// ---- classification --------------------------------------------------------

// classify maps a rel path to its family, "" when not gomachost's:
// "os_release" for SystemVersion.plist, "hostname" for the
// SystemConfiguration preferences, "globalprefs" for the SYSTEM
// .GlobalPreferences.plist (time zone + locale; a user's own copy under
// Users/ is not the host's).
func classify(rel string) string {
	rel = strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(rel)
	dir := filepath.Base(filepath.Dir(rel))
	switch base {
	case "systemversion.plist":
		if dir == "coreservices" {
			return "os_release"
		}
	case "preferences.plist":
		if dir == "systemconfiguration" {
			return "hostname"
		}
	case ".globalpreferences.plist":
		if dir == "preferences" && !strings.HasPrefix(rel, "users/") && !strings.Contains(rel, "/users/") {
			return "globalprefs"
		}
	}
	return ""
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

// parseSystemVersion emits one os_release row: ProductName / ProductVersion
// / ProductBuildVersion lifted, every key kept under Fields.
func parseSystemVersion(rd io.Reader, w *record.Writer) (int, error) {
	d, err := load(rd)
	if err != nil {
		return 0, err
	}
	rec := &hostRecord{Fields: map[string]string{}}
	rec.RecordType = "os_release"
	for k, v := range d {
		rec.Fields[k] = plist.Render(v)
	}
	rec.Name = plist.String(d["ProductName"])
	rec.VersionID = plist.String(d["ProductVersion"])
	if rec.Name == "" && rec.VersionID == "" {
		return 0, fmt.Errorf("no ProductName/ProductVersion: not a SystemVersion.plist")
	}
	switch strings.ToLower(rec.Name) {
	case "macos", "mac os x", "os x":
		rec.ID = "macos"
	default:
		rec.ID = strings.ToLower(strings.ReplaceAll(rec.Name, " ", ""))
	}
	rec.PrettyName = strings.TrimSpace(rec.Name + " " + rec.VersionID)
	if b := plist.String(d["ProductBuildVersion"]); b != "" {
		rec.PrettyName += " (" + b + ")"
	}
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

// parsePreferences emits one hostname row from System.System (HostName,
// LocalHostName, ComputerName) and the hardware Model.
func parsePreferences(rd io.Reader, w *record.Writer) (int, error) {
	d, err := load(rd)
	if err != nil {
		return 0, err
	}
	rec := &hostRecord{}
	rec.RecordType = "hostname"
	rec.Model = plist.String(d["Model"])
	if sys := plist.Dict(plist.Dict(d["System"])["System"]); sys != nil {
		rec.Hostname = plist.String(sys["HostName"])
		rec.LocalHostName = plist.String(sys["LocalHostName"])
		rec.ComputerName = plist.String(sys["ComputerName"])
	}
	if net := plist.Dict(plist.Dict(plist.Dict(d["System"])["Network"])["HostNames"]); net != nil && rec.LocalHostName == "" {
		rec.LocalHostName = plist.String(net["LocalHostName"])
	}
	if rec.Hostname == "" {
		rec.Hostname = rec.LocalHostName
	}
	if rec.Hostname == "" {
		rec.Hostname = rec.ComputerName
	}
	if rec.Hostname == "" && rec.Model == "" {
		return 0, fmt.Errorf("no host names: not a SystemConfiguration preferences.plist")
	}
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

// parseGlobalPrefs emits a timezone row (the selected city's zone name)
// and a locale row (AppleLocale, Country, AppleLanguages) when present.
func parseGlobalPrefs(rd io.Reader, w *record.Writer) (int, error) {
	d, err := load(rd)
	if err != nil {
		return 0, err
	}
	n := 0
	// com.apple.TimeZonePref.Last_Selected_City: [lat, lon, ?, zone, country, city, …]
	if city := plist.Strings(d["com.apple.TimeZonePref.Last_Selected_City"]); len(city) > 3 && city[3] != "" {
		rec := &hostRecord{}
		rec.RecordType = "timezone"
		rec.Timezone = city[3]
		if len(city) > 5 {
			rec.City = city[5]
		}
		if len(city) > 4 {
			rec.Country = city[4]
		}
		if err := w.Write(rec); err != nil {
			return n, err
		}
		n++
	}
	if lang := plist.String(d["AppleLocale"]); lang != "" || plist.String(d["Country"]) != "" {
		rec := &hostRecord{}
		rec.RecordType = "locale"
		rec.Lang = lang
		rec.Country = plist.String(d["Country"])
		rec.Languages = plist.Strings(d["AppleLanguages"])
		if err := w.Write(rec); err != nil {
			return n, err
		}
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("no time zone or locale keys: not the system .GlobalPreferences.plist")
	}
	return n, nil
}

func parseByFamily(rd io.Reader, family string, w *record.Writer) (int, error) {
	switch family {
	case "os_release":
		return parseSystemVersion(rd, w)
	case "hostname":
		return parsePreferences(rd, w)
	case "globalprefs":
		return parseGlobalPrefs(rd, w)
	}
	return 0, fmt.Errorf("unknown family %q", family)
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "gomachost",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			return classify(rel) != ""
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		rel, _ := filepath.Rel(cfg.InputDir, item)
		f, err := os.Open(item)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return parseByFamily(f, classify(filepath.ToSlash(rel)), w)
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one property list (family from its path)")
		dir   = flag.String("d", "", "recurse a directory")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gomachost                          (env-driven batch mode)\n"+
			"       gomachost -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		family := classify(rel)
		if family == "" {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gomachost: %s: not a gomachost file, skipped\n", path)
			}
			return
		}
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "gomachost", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseByFamily(f, family, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gomachost: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return classify(rel) != "" })
		if err != nil {
			fmt.Fprintf(os.Stderr, "gomachost: %v\n", err)
			os.Exit(1)
		}
		sort.Strings(items)
		for _, it := range items {
			rel, rerr := filepath.Rel(*dir, it)
			if rerr != nil {
				rel = it
			}
			one(it, filepath.ToSlash(rel))
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "gomachost: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
