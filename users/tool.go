// gousers — Linux account-and-access surface parser for the DX_DFIR
// pipeline (docs/linux §4). Finds passwd, shadow, group, gshadow, sudoers
// (with sudoers.d), sshd_config (with drop-ins), authorized_keys and
// known_hosts files under the input tree and emits typed records per line.
//
// Rules (docs/linux §4.1): native values verbatim — a shadow crypt string,
// a NIS '+' entry, a hashed known_hosts pattern are recorded as found, and
// judging them (locked account, weak hash) is byakugan's. A real uid 0 is a
// value, never a blank; a field the artefact does not carry is omitted.
// Shadow day-counts are additionally rendered as dates (the record's own
// EventTime, TimeKind password_change). SSH keys are identified by their
// standard SHA256 fingerprint rendering — a rendering of the artefact's own
// bytes, not an enrichment.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOUSERS_* environment. The argv flags are the
// debug pass-through:
//
//	gousers -f FILE | -d DIR [-q]
package users

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Get-Sybers/gopinfo/batch"
	"github.com/Get-Sybers/gopinfo/discover"
	"github.com/Get-Sybers/gopinfo/record"
	"github.com/Get-Sybers/gopinfo/tstamp"
)

// userRecord is the one record shape of gousers; RecordType says which
// family a row is and which fields are populated.
type userRecord struct {
	record.Envelope
	// passwd / shadow / group / gshadow
	Username       string   `json:"Username,omitempty"`
	PasswordField  string   `json:"PasswordField,omitempty"`
	PasswordCrypt  string   `json:"PasswordCrypt,omitempty"`
	UID            *int64   `json:"UID,omitempty"`
	GID            *int64   `json:"GID,omitempty"`
	GECOS          string   `json:"GECOS,omitempty"`
	HomeDir        string   `json:"HomeDir,omitempty"`
	Shell          string   `json:"Shell,omitempty"`
	Class          string   `json:"Class,omitempty"` // BSD master.passwd login class
	GroupName      string   `json:"GroupName,omitempty"`
	Members        []string `json:"Members,omitempty"`
	Admins         []string `json:"Admins,omitempty"`
	LastChangeDays *int64   `json:"LastChangeDays,omitempty"`
	MinDays        *int64   `json:"MinDays,omitempty"`
	MaxDays        *int64   `json:"MaxDays,omitempty"`
	WarnDays       *int64   `json:"WarnDays,omitempty"`
	InactiveDays   *int64   `json:"InactiveDays,omitempty"`
	ExpireDays     *int64   `json:"ExpireDays,omitempty"`
	ExpireTime     string   `json:"ExpireTime,omitempty"`
	// sudoers
	Users      []string `json:"Users,omitempty"`
	Hosts      []string `json:"Hosts,omitempty"`
	RunAs      string   `json:"RunAs,omitempty"`
	Tags       []string `json:"Tags,omitempty"`
	Commands   []string `json:"Commands,omitempty"`
	AliasType  string   `json:"AliasType,omitempty"`
	AliasName  string   `json:"AliasName,omitempty"`
	Parameters string   `json:"Parameters,omitempty"`
	Include    string   `json:"Include,omitempty"`
	// sshd_config
	Keyword      string `json:"Keyword,omitempty"`
	Value        string `json:"Value,omitempty"`
	MatchContext string `json:"MatchContext,omitempty"`
	// authorized_keys / known_hosts
	Options     string `json:"Options,omitempty"`
	KeyType     string `json:"KeyType,omitempty"`
	Fingerprint string `json:"Fingerprint,omitempty"`
	Comment     string `json:"Comment,omitempty"`
	HostPattern string `json:"HostPattern,omitempty"`
	Hashed      bool   `json:"Hashed,omitempty"`
	Marker      string `json:"Marker,omitempty"`
	// every family
	Line int    `json:"Line"`
	Raw  string `json:"Raw,omitempty"`
}

// ---- classification --------------------------------------------------------

// classify maps a file's rel path to its family, "" when not gousers'.
func classify(rel string) string {
	rel = strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(rel)
	dir := filepath.Base(filepath.Dir(rel))
	if dir == "pam.d" { // etc/pam.d/passwd, /sudo, /sshd are PAM stacks, not the tables
		return ""
	}
	switch base {
	case "passwd", "passwd-":
		return "passwd"
	case "master.passwd":
		return "master_passwd"
	case "shadow", "shadow-":
		return "shadow"
	case "group", "group-":
		return "group"
	case "gshadow", "gshadow-":
		return "gshadow"
	case "sudoers":
		return "sudoers"
	case "sshd_config":
		return "sshd_config"
	case "authorized_keys", "authorized_keys2":
		return "authorized_keys"
	case "known_hosts", "ssh_known_hosts":
		return "known_hosts"
	}
	if dir == "sudoers.d" {
		return "sudoers"
	}
	if dir == "sshd_config.d" && strings.HasSuffix(base, ".conf") {
		return "sshd_config"
	}
	return ""
}

// ---- line parsers ----------------------------------------------------------

func num(s string) *int64 {
	if s == "" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePasswdLine(f []string, rec *userRecord) bool {
	if len(f) != 7 {
		return false
	}
	rec.RecordType = "account"
	rec.Username, rec.PasswordField = f[0], f[1]
	rec.UID, rec.GID = num(f[2]), num(f[3])
	rec.GECOS, rec.HomeDir, rec.Shell = f[4], f[5], f[6]
	return true
}

// parseMasterPasswdLine reads a BSD master.passwd row (macOS carries one
// for its system accounts): name, hash, uid, gid, class, change, expire,
// gecos, home, shell — change and expire as Unix seconds.
func parseMasterPasswdLine(f []string, rec *userRecord) bool {
	if len(f) != 10 {
		return false
	}
	rec.RecordType = "account"
	rec.Username, rec.PasswordField = f[0], f[1]
	rec.UID, rec.GID = num(f[2]), num(f[3])
	rec.Class = f[4]
	rec.GECOS, rec.HomeDir, rec.Shell = f[7], f[8], f[9]
	if n := num(f[5]); n != nil && *n > 0 {
		rec.EventTime = tstamp.Unix(*n, 0)
		rec.TimeKind = "password_change"
	}
	if n := num(f[6]); n != nil && *n > 0 {
		rec.ExpireTime = tstamp.Unix(*n, 0)
	}
	return true
}

func parseShadowLine(f []string, rec *userRecord) bool {
	if len(f) != 9 {
		return false
	}
	rec.RecordType = "shadow"
	rec.Username, rec.PasswordCrypt = f[0], f[1]
	rec.LastChangeDays, rec.MinDays, rec.MaxDays = num(f[2]), num(f[3]), num(f[4])
	rec.WarnDays, rec.InactiveDays, rec.ExpireDays = num(f[5]), num(f[6]), num(f[7])
	if rec.LastChangeDays != nil {
		rec.EventTime = tstamp.Days(*rec.LastChangeDays)
		if rec.EventTime != "" {
			rec.TimeKind = "password_change"
		}
	}
	if rec.ExpireDays != nil {
		rec.ExpireTime = tstamp.Days(*rec.ExpireDays)
	}
	return true
}

func parseGroupLine(f []string, rec *userRecord) bool {
	if len(f) != 4 {
		return false
	}
	rec.RecordType = "group"
	rec.GroupName, rec.PasswordField = f[0], f[1]
	rec.GID, rec.Members = num(f[2]), splitList(f[3])
	return true
}

func parseGshadowLine(f []string, rec *userRecord) bool {
	if len(f) != 4 {
		return false
	}
	rec.RecordType = "gshadow"
	rec.GroupName, rec.PasswordCrypt = f[0], f[1]
	rec.Admins, rec.Members = splitList(f[2]), splitList(f[3])
	return true
}

var (
	aliasRe = regexp.MustCompile(`^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\s+(\S+)\s*=\s*(.+)$`)
	ruleRe  = regexp.MustCompile(`^(.+?)\s+(\S+)\s*=\s*(?:\(([^)]*)\)\s*)?(.+)$`)
	tagRe   = regexp.MustCompile(`^(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW|INTERCEPT|NOINTERCEPT):\s*(.*)$`)
)

func parseSudoersLine(line string, rec *userRecord) bool {
	rec.Raw = line
	switch {
	case strings.HasPrefix(line, "#include") || strings.HasPrefix(line, "@include"):
		rec.RecordType = "sudoers_include"
		rec.Include = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(
			strings.TrimPrefix(strings.TrimPrefix(line, "#includedir"), "#include"),
			"@includedir"), "@include"))
		return true
	case strings.HasPrefix(line, "#"):
		return false // a comment, not an entry
	case strings.HasPrefix(line, "Defaults"):
		rec.RecordType = "sudoers_default"
		rec.Parameters = strings.TrimSpace(strings.TrimPrefix(line, "Defaults"))
		return true
	}
	if m := aliasRe.FindStringSubmatch(line); m != nil {
		rec.RecordType = "sudoers_alias"
		rec.AliasType, rec.AliasName, rec.Members = m[1], m[2], splitList(m[3])
		return true
	}
	rec.RecordType = "sudoers_rule"
	if m := ruleRe.FindStringSubmatch(line); m != nil {
		rec.Users, rec.Hosts, rec.RunAs = splitList(m[1]), splitList(m[2]), strings.TrimSpace(m[3])
		rest := strings.TrimSpace(m[4])
		for {
			tm := tagRe.FindStringSubmatch(rest)
			if tm == nil {
				break
			}
			rec.Tags = append(rec.Tags, tm[1])
			rest = strings.TrimSpace(tm[2])
		}
		rec.Commands = splitList(rest)
	}
	return true // an unparsed spec still emits, Raw only
}

// sshKeyFingerprint renders the standard OpenSSH SHA256 fingerprint of a
// base64 key blob; "" when the blob does not decode.
func sshKeyFingerprint(b64 string) string {
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

var keyTypeRe = regexp.MustCompile(`^(sk-)?(ssh|ecdsa)-[a-z0-9-]+(@[a-z0-9.-]+)?$`)

// parseAuthorizedKey handles `[options] keytype base64 [comment]`, options
// possibly holding quoted commas.
func parseAuthorizedKey(line string, rec *userRecord) bool {
	rec.RecordType = "authorized_key"
	rec.Raw = line
	fields := splitRespectingQuotes(line)
	i := 0
	if len(fields) > 1 && !keyTypeRe.MatchString(fields[0]) {
		rec.Options = fields[0]
		i = 1
	}
	if len(fields) < i+2 || !keyTypeRe.MatchString(fields[i]) {
		return false
	}
	rec.KeyType = fields[i]
	rec.Fingerprint = sshKeyFingerprint(fields[i+1])
	if len(fields) > i+2 {
		rec.Comment = strings.Join(fields[i+2:], " ")
	}
	return true
}

func parseKnownHost(line string, rec *userRecord) bool {
	rec.RecordType = "known_host"
	rec.Raw = line
	fields := strings.Fields(line)
	i := 0
	if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		rec.Marker = fields[0]
		i = 1
	}
	if len(fields) < i+3 {
		return false
	}
	rec.HostPattern = fields[i]
	rec.Hashed = strings.HasPrefix(rec.HostPattern, "|1|")
	rec.KeyType = fields[i+1]
	rec.Fingerprint = sshKeyFingerprint(fields[i+2])
	if len(fields) > i+3 {
		rec.Comment = strings.Join(fields[i+3:], " ")
	}
	return true
}

// splitRespectingQuotes splits on spaces outside double quotes (the
// authorized_keys options field carries quoted commas and spaces).
func splitRespectingQuotes(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ---- file parser -----------------------------------------------------------

// parseFile parses one classified file, one record per meaningful line.
func parseFile(rd io.Reader, family string, w *record.Writer, warnf func(string, ...interface{})) (int, error) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	emitted, lineNo, malformed := 0, 0, 0
	matchContext := ""
	var pending string // sudoers/sshd continuation
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		if pending != "" {
			line = pending + " " + strings.TrimSpace(line)
			pending = ""
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if (family == "sudoers" || family == "sshd_config") && strings.HasSuffix(trimmed, "\\") {
			pending = strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
			continue
		}
		rec := &userRecord{Line: lineNo}
		ok := false
		switch family {
		case "passwd", "master_passwd", "shadow", "group", "gshadow":
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			f := strings.Split(trimmed, ":")
			switch family {
			case "passwd":
				ok = parsePasswdLine(f, rec)
			case "master_passwd":
				ok = parseMasterPasswdLine(f, rec)
			case "shadow":
				ok = parseShadowLine(f, rec)
			case "group":
				ok = parseGroupLine(f, rec)
			case "gshadow":
				ok = parseGshadowLine(f, rec)
			}
			if !ok {
				malformed++
				continue
			}
		case "sudoers":
			ok = parseSudoersLine(trimmed, rec)
			if !ok {
				continue // comment
			}
		case "sshd_config":
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			kv := strings.SplitN(trimmed, " ", 2)
			key := strings.TrimSuffix(kv[0], "=")
			rec.RecordType = "sshd_config"
			rec.Keyword = key
			if len(kv) > 1 {
				rec.Value = strings.TrimSpace(kv[1])
			}
			if strings.EqualFold(key, "Match") {
				matchContext = rec.Value
			} else {
				rec.MatchContext = matchContext
			}
			ok = true
		case "authorized_keys":
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if ok = parseAuthorizedKey(trimmed, rec); !ok {
				malformed++
				continue
			}
		case "known_hosts":
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if ok = parseKnownHost(trimmed, rec); !ok {
				malformed++
				continue
			}
		}
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	if err := sc.Err(); err != nil {
		return emitted, err
	}
	if emitted == 0 && malformed > 0 {
		return 0, fmt.Errorf("no %s records parsed (%d malformed lines)", family, malformed)
	}
	if malformed > 0 {
		warnf("%d malformed %s lines skipped", malformed, family)
	}
	return emitted, nil
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "gousers",
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
		return parseFile(f, classify(rel), w, func(format string, args ...interface{}) {
			cfg.Logf(batch.LogWarn, item+": "+format, args...)
		})
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one file (family from its name)")
		dir   = flag.String("d", "", "recurse a directory")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gousers                            (env-driven batch mode)\n"+
			"       gousers -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	warnf := func(f string, a ...interface{}) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "gousers: "+f+"\n", a...)
		}
	}
	failed := 0
	one := func(path, rel string) {
		family := classify(rel)
		if family == "" {
			warnf("%s: not a gousers file, skipped", path)
			return
		}
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "gousers", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseFile(f, family, w, warnf)
			f.Close()
		}
		if err != nil {
			warnf("%s: %v", path, err)
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return classify(rel) != "" })
		if err != nil {
			fmt.Fprintf(os.Stderr, "gousers: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "gousers: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
