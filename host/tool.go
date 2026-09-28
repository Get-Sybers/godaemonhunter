// gohost — host identity and storage-mapping parser for the DX_DFIR
// pipeline (docs/linux §4). Extracts the facts that anchor every other
// record: who the imaged host is (os-release, hostname, machine-id,
// timezone, locale) and how its durable volume identities map to names —
// the role a drive serial plays on Windows: fstab rows tie a filesystem
// UUID or LABEL to a mount point, crypttab rows tie an encrypted device to
// its mapped name.
//
// Rules (docs/linux §4.1): extraction only. The parser hands byakugan the
// host's timezone; APPLYING it to naive log timestamps is byakugan's. It
// hands the UUID→mountpoint table; JOINING it against a volume's fsuuid
// (Origin.FSUUID, the access layer's manifest) is byakugan's.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOHOST_* environment. The argv flags are the
// debug pass-through:
//
//	gohost -f FILE | -d DIR [-q]
package host

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/get-sybers/gopinfo/batch"
	"github.com/get-sybers/gopinfo/discover"
	"github.com/get-sybers/gopinfo/record"
	"github.com/get-sybers/gopinfo/tstamp"
)

// hostRecord is the one record shape; RecordType says which family a row
// is and which fields are populated.
type hostRecord struct {
	record.Envelope
	// os_release / locale (lifted keys + the full set)
	Name       string            `json:"Name,omitempty"`
	ID         string            `json:"ID,omitempty"`
	VersionID  string            `json:"VersionID,omitempty"`
	PrettyName string            `json:"PrettyName,omitempty"`
	Lang       string            `json:"Lang,omitempty"`
	Fields     map[string]string `json:"Fields,omitempty"`
	// hostname / machine_id / timezone
	Hostname  string `json:"Hostname,omitempty"`
	MachineID string `json:"MachineID,omitempty"`
	Timezone  string `json:"Timezone,omitempty"`
	PosixTZ   string `json:"PosixTZ,omitempty"`
	// fstab_entry / crypttab_entry
	Device     string `json:"Device,omitempty"`
	SpecType   string `json:"SpecType,omitempty"`
	UUID       string `json:"UUID,omitempty"`
	Label      string `json:"Label,omitempty"`
	MountPoint string `json:"MountPoint,omitempty"`
	FSType     string `json:"FSType,omitempty"`
	Options    string `json:"Options,omitempty"`
	Dump       string `json:"Dump,omitempty"`
	Pass       string `json:"Pass,omitempty"`
	MapperName string `json:"MapperName,omitempty"`
	KeyFile    string `json:"KeyFile,omitempty"`
	Line       int    `json:"Line,omitempty"`
	Raw        string `json:"Raw,omitempty"`
}

// ---- classification --------------------------------------------------------

// classify maps a rel path to its family, "" when not gohost's.
func classify(rel string) string {
	rel = strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(rel)
	dir := filepath.Base(filepath.Dir(rel))
	switch base {
	case "os-release":
		return "os_release"
	case "hostname":
		if dir == "etc" || dir == "." {
			return "hostname"
		}
	case "machine-id":
		return "machine_id"
	case "timezone":
		return "timezone"
	case "localtime":
		return "localtime"
	case "locale.conf":
		return "locale"
	case "locale":
		if dir == "default" {
			return "locale"
		}
	case "fstab":
		return "fstab"
	case "crypttab":
		return "crypttab"
	}
	return ""
}

// ---- parsers ---------------------------------------------------------------

// parseKVFile parses shell-style KEY=value files (os-release, locale),
// one record per file with the well-known keys lifted.
func parseKVFile(rd io.Reader, family string, w *record.Writer) (int, error) {
	rec := &hostRecord{Fields: map[string]string{}}
	rec.RecordType = family
	sc := bufio.NewScanner(rd)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		k = strings.TrimSpace(k)
		switch {
		case family == "os_release" && k == "NAME":
			rec.Name = v
		case family == "os_release" && k == "ID":
			rec.ID = v
		case family == "os_release" && k == "VERSION_ID":
			rec.VersionID = v
		case family == "os_release" && k == "PRETTY_NAME":
			rec.PrettyName = v
		case family == "locale" && k == "LANG":
			rec.Lang = v
		default:
			rec.Fields[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if len(rec.Fields) == 0 {
		rec.Fields = nil
	}
	if rec.Name == "" && rec.ID == "" && rec.Lang == "" && rec.Fields == nil {
		return 0, fmt.Errorf("no KEY=value pairs: not an %s file", family)
	}
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

// parseOneLiner handles hostname / machine-id / timezone: the first
// non-comment line is the value.
func parseOneLiner(rd io.Reader, family string, w *record.Writer) (int, error) {
	sc := bufio.NewScanner(rd)
	for sc.Scan() {
		v := strings.TrimSpace(sc.Text())
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		rec := &hostRecord{}
		rec.RecordType = family
		switch family {
		case "hostname":
			rec.Hostname = v
		case "machine_id":
			if !machineIDRe.MatchString(v) {
				return 0, fmt.Errorf("not a machine-id (%q)", v)
			}
			rec.MachineID = v
		case "timezone":
			rec.Timezone = v
		}
		if err := w.Write(rec); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("empty %s file", family)
}

var machineIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// parseTZif reads a staged /etc/localtime. The zone NAME lives in the
// symlink target, which a staged copy loses — what the TZif file itself
// carries is the trailing POSIX TZ rule (v2+), extracted verbatim.
func parseTZif(rd io.Reader, w *record.Writer) (int, error) {
	b, err := io.ReadAll(io.LimitReader(rd, 1<<20))
	if err != nil {
		return 0, err
	}
	rec := &hostRecord{}
	rec.RecordType = "timezone"
	if len(b) < 4 || string(b[0:4]) != "TZif" {
		// a symlink staged as its target text ("/var/db/timezone/zoneinfo/
		// Europe/Tallinn", "../usr/share/zoneinfo/UTC"): the zone name is
		// what follows zoneinfo/
		target := strings.TrimSpace(string(b))
		if i := strings.LastIndex(target, "zoneinfo/"); i >= 0 && len(target) < 256 && !strings.ContainsAny(target, "\x00\n") {
			rec.Timezone = target[i+len("zoneinfo/"):]
			if err := w.Write(rec); err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, fmt.Errorf("not a TZif file")
	}
	// v2+ footer: ...\n<posix tz>\n at the very end of the file.
	if b[len(b)-1] == '\n' {
		body := b[:len(b)-1]
		if i := strings.LastIndexByte(string(body), '\n'); i >= 0 {
			if tz := strings.TrimSpace(string(body[i+1:])); tz != "" && !strings.ContainsAny(tz, "\x00") {
				rec.PosixTZ = tz
			}
		}
	}
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

// specType splits an fstab/crypttab device spec into its addressing form.
func specType(dev string, rec *hostRecord) {
	switch {
	case strings.HasPrefix(dev, "UUID="):
		rec.SpecType, rec.UUID = "uuid", dev[5:]
	case strings.HasPrefix(dev, "LABEL="):
		rec.SpecType, rec.Label = "label", dev[6:]
	case strings.HasPrefix(dev, "PARTUUID="):
		rec.SpecType, rec.UUID = "partuuid", dev[9:]
	case strings.HasPrefix(dev, "PARTLABEL="):
		rec.SpecType, rec.Label = "partlabel", dev[10:]
	case strings.HasPrefix(dev, "/dev/disk/by-uuid/"):
		rec.SpecType, rec.UUID = "uuid", strings.TrimPrefix(dev, "/dev/disk/by-uuid/")
	case strings.HasPrefix(dev, "/dev/disk/by-label/"):
		rec.SpecType, rec.Label = "label", strings.TrimPrefix(dev, "/dev/disk/by-label/")
	case strings.HasPrefix(dev, "/"):
		rec.SpecType = "path"
	case strings.Contains(dev, ":/") || strings.HasPrefix(dev, "//"):
		rec.SpecType = "remote"
	default:
		rec.SpecType = "other"
	}
}

// parseFstab emits one fstab_entry per row: the durable volume identity
// (UUID/LABEL) tied to its mount point — the Windows drive-serial→letter
// mapping, Linux edition.
func parseFstab(rd io.Reader, w *record.Writer) (int, error) {
	sc := bufio.NewScanner(rd)
	emitted, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		rec := &hostRecord{Line: lineNo}
		rec.RecordType = "fstab_entry"
		if len(f) < 2 {
			rec.Raw = line
		} else {
			rec.Device = f[0]
			specType(f[0], rec)
			rec.MountPoint = f[1]
			if len(f) > 2 {
				rec.FSType = f[2]
			}
			if len(f) > 3 {
				rec.Options = f[3]
			}
			if len(f) > 4 {
				rec.Dump = f[4]
			}
			if len(f) > 5 {
				rec.Pass = f[5]
			}
		}
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

// parseCrypttab emits one crypttab_entry per row: mapped name, backing
// device (UUID form split out), key source and options.
func parseCrypttab(rd io.Reader, w *record.Writer) (int, error) {
	sc := bufio.NewScanner(rd)
	emitted, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		rec := &hostRecord{Line: lineNo}
		rec.RecordType = "crypttab_entry"
		if len(f) < 2 {
			rec.Raw = line
		} else {
			rec.MapperName = f[0]
			rec.Device = f[1]
			specType(f[1], rec)
			if len(f) > 2 && f[2] != "none" && f[2] != "-" {
				rec.KeyFile = f[2]
			}
			if len(f) > 3 {
				rec.Options = f[3]
			}
		}
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

func parseByFamily(rd io.Reader, family string, w *record.Writer) (int, error) {
	switch family {
	case "os_release", "locale":
		return parseKVFile(rd, family, w)
	case "hostname", "machine_id", "timezone":
		return parseOneLiner(rd, family, w)
	case "localtime":
		return parseTZif(rd, w)
	case "fstab":
		return parseFstab(rd, w)
	case "crypttab":
		return parseCrypttab(rd, w)
	}
	return 0, fmt.Errorf("unknown family %q", family)
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "gohost",
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
		file  = flag.String("f", "", "parse one host-config file (family from its path)")
		dir   = flag.String("d", "", "recurse a directory")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gohost                             (env-driven batch mode)\n"+
			"       gohost -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		family := classify(rel)
		if family == "" {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gohost: %s: not a gohost file, skipped\n", path)
			}
			return
		}
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "gohost", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseByFamily(f, family, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gohost: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return classify(rel) != "" })
		if err != nil {
			fmt.Fprintf(os.Stderr, "gohost: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "gohost: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
