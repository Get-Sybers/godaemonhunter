// gomacusers — macOS local-account parser for the DX_DFIR pipeline: the
// Mac counterpart of gousers in Layer 1 (docs/linux §4). Reads the
// OpenDirectory local node — private/var/db/dslocal/nodes/Default/users/
// *.plist and groups/*.plist, one property list per account — and emits
// the SAME account and group record types gousers does, so the knowledge
// store resolves a Mac's uids and gids exactly as a Linux host's.
//
// Rules (docs/linux §4.1): native values verbatim — the authentication
// authority strings, the generated UUID, the SMB SID; the password hash
// blob (ShadowHashData) is reported present, never carried. The account
// policy blob (a nested plist) gives the password-set time, the record's
// own EventTime (TimeKind password_change), the creation time and the
// failed-login counters.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOMACUSERS_* environment. The argv flags are the
// debug pass-through:
//
//	gomacusers -f FILE | -d DIR [-q]
package macusers

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Get-Sybers/gopinfo/batch"
	"github.com/Get-Sybers/gopinfo/discover"
	"github.com/Get-Sybers/gopinfo/plist"
	"github.com/Get-Sybers/gopinfo/record"
	"github.com/Get-Sybers/gopinfo/tstamp"
)

// userRecord is the one record shape; RecordType is account or group. The
// shared field names (Username, UID, GID, GroupName, Members, …) match
// gousers' so the knowledge store reads both.
type userRecord struct {
	record.Envelope
	// account
	Username                string   `json:"Username,omitempty"`
	UID                     *int64   `json:"UID,omitempty"`
	GID                     *int64   `json:"GID,omitempty"`
	GECOS                   string   `json:"GECOS,omitempty"`
	HomeDir                 string   `json:"HomeDir,omitempty"`
	Shell                   string   `json:"Shell,omitempty"`
	AuthenticationAuthority []string `json:"AuthenticationAuthority,omitempty"`
	HasShadowHash           bool     `json:"HasShadowHash,omitempty"`
	IsHidden                bool     `json:"IsHidden,omitempty"`
	Picture                 string   `json:"Picture,omitempty"`
	AccountCreated          string   `json:"AccountCreated,omitempty"`
	PasswordLastSet         string   `json:"PasswordLastSet,omitempty"`
	FailedLoginCount        *int64   `json:"FailedLoginCount,omitempty"`
	FailedLoginTime         string   `json:"FailedLoginTime,omitempty"`
	// group
	GroupName    string   `json:"GroupName,omitempty"`
	Members      []string `json:"Members,omitempty"`
	GroupMembers []string `json:"GroupMembers,omitempty"`
	// both
	Aliases      []string `json:"Aliases,omitempty"`
	GeneratedUID string   `json:"GeneratedUID,omitempty"`
	SMBSID       string   `json:"SMBSID,omitempty"`
	Keys         []string `json:"Keys,omitempty"`
}

// ---- classification --------------------------------------------------------

// classify maps a rel path to "account" or "group": a .plist under the
// users/ or groups/ directory of a dslocal node (…/dslocal/nodes/<node>/).
func classify(rel string) string {
	rel = strings.ToLower(filepath.ToSlash(rel))
	if !strings.HasSuffix(rel, ".plist") {
		return ""
	}
	dir := filepath.Dir(rel)
	if !strings.Contains(dir, "dslocal/nodes/") {
		return ""
	}
	switch filepath.Base(dir) {
	case "users":
		return "account"
	case "groups":
		return "group"
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

func keys(d map[string]any) []string {
	out := make([]string, 0, len(d))
	for k := range d {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func intPtr(v any) *int64 {
	if n, ok := plist.Int(v); ok {
		return &n
	}
	return nil
}

// parseAccount emits one account row from a users/<name>.plist.
func parseAccount(rd io.Reader, w *record.Writer) (int, error) {
	d, err := load(rd)
	if err != nil {
		return 0, err
	}
	names := plist.Strings(d["name"])
	if len(names) == 0 {
		return 0, fmt.Errorf("no name attribute: not a dslocal user record")
	}
	rec := &userRecord{Keys: keys(d)}
	rec.RecordType = "account"
	rec.Username = names[0]
	rec.Aliases = names[1:]
	rec.UID = intPtr(d["uid"])
	rec.GID = intPtr(d["gid"])
	rec.GECOS = plist.String(d["realname"])
	rec.HomeDir = plist.String(d["home"])
	rec.Shell = plist.String(d["shell"])
	rec.AuthenticationAuthority = plist.Strings(d["authentication_authority"])
	rec.GeneratedUID = plist.String(d["generateduid"])
	rec.SMBSID = plist.String(d["smb_sid"])
	rec.Picture = plist.String(d["picture"])
	_, rec.HasShadowHash = d["ShadowHashData"]
	if b, ok := plist.Bool(d["IsHidden"]); ok {
		rec.IsHidden = b
	}
	// accountPolicyData: a plist inside a data attribute
	for _, blob := range plist.Array(d["accountPolicyData"]) {
		raw, ok := blob.([]byte)
		if !ok {
			continue
		}
		pv, err := plist.Decode(raw)
		if err != nil {
			continue
		}
		p := plist.Dict(pv)
		if t, ok := plist.Time(p["creationTime"]); ok {
			rec.AccountCreated = tstamp.ISO8601(t)
		}
		if t, ok := plist.Time(p["passwordLastSetTime"]); ok {
			rec.PasswordLastSet = tstamp.ISO8601(t)
			rec.EventTime, rec.TimeKind = rec.PasswordLastSet, "password_change"
		}
		rec.FailedLoginCount = intPtr(p["failedLoginCount"])
		if t, ok := plist.Time(p["failedLoginTimestamp"]); ok {
			rec.FailedLoginTime = tstamp.ISO8601(t)
		}
		break
	}
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

// parseGroup emits one group row from a groups/<name>.plist.
func parseGroup(rd io.Reader, w *record.Writer) (int, error) {
	d, err := load(rd)
	if err != nil {
		return 0, err
	}
	names := plist.Strings(d["name"])
	if len(names) == 0 {
		return 0, fmt.Errorf("no name attribute: not a dslocal group record")
	}
	rec := &userRecord{Keys: keys(d)}
	rec.RecordType = "group"
	rec.GroupName = names[0]
	rec.Aliases = names[1:]
	rec.GID = intPtr(d["gid"])
	rec.GECOS = plist.String(d["realname"])
	rec.Members = plist.Strings(d["users"])
	rec.GroupMembers = plist.Strings(d["groupmembers"])
	rec.GeneratedUID = plist.String(d["generateduid"])
	rec.SMBSID = plist.String(d["smb_sid"])
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

func parseByFamily(rd io.Reader, family string, w *record.Writer) (int, error) {
	switch family {
	case "account":
		return parseAccount(rd, w)
	case "group":
		return parseGroup(rd, w)
	}
	return 0, fmt.Errorf("unknown family %q", family)
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "gomacusers",
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
		file  = flag.String("f", "", "parse one dslocal record (family from its path)")
		dir   = flag.String("d", "", "recurse a directory")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gomacusers                         (env-driven batch mode)\n"+
			"       gomacusers -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		family := classify(rel)
		if family == "" {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gomacusers: %s: not a gomacusers file, skipped\n", path)
			}
			return
		}
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "gomacusers", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseByFamily(f, family, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gomacusers: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return classify(rel) != "" })
		if err != nil {
			fmt.Fprintf(os.Stderr, "gomacusers: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "gomacusers: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
