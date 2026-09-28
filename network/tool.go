// gonetwork — network-configuration parser for the DX_DFIR pipeline
// (docs/linux §4): the network surface of a Linux image as typed records.
// Name resolution (hosts, resolv.conf, nsswitch), interface and connection
// profiles (ifupdown interfaces, systemd-networkd, NetworkManager
// system-connections, netplan), TCP wrappers (hosts.allow/deny) and
// persisted firewall state (iptables-save files; nftables.conf captured).
//
// Rules (docs/linux §4.1): extraction only, values verbatim — a hosts
// override, a rogue nameserver, a static profile or an unexpected firewall
// rule is byakugan's to judge, this parser's to surface. Connection
// profiles are recorded as the file states them, secrets included: this is
// evidence extraction, the same rule shadow crypt strings follow.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GONETWORK_* environment. The argv flags are the
// debug pass-through:
//
//	gonetwork -f FILE | -d DIR [-q]
package network

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

// netRecord is the one record shape; RecordType says which family a row is.
type netRecord struct {
	record.Envelope
	// hosts / resolv / nsswitch / tcpwrappers
	IPAddress string   `json:"IPAddress,omitempty"`
	Hostnames []string `json:"Hostnames,omitempty"`
	Directive string   `json:"Directive,omitempty"`
	Value     string   `json:"Value,omitempty"`
	Database  string   `json:"Database,omitempty"`
	Sources   []string `json:"Sources,omitempty"`
	Daemons   string   `json:"Daemons,omitempty"`
	Clients   string   `json:"Clients,omitempty"`
	Option    string   `json:"Option,omitempty"`
	// interface / connection profiles
	Interface string            `json:"Interface,omitempty"`
	Family    string            `json:"Family,omitempty"`
	Method    string            `json:"Method,omitempty"`
	Section   string            `json:"Section,omitempty"`
	Name      string            `json:"Name,omitempty"`
	ConnType  string            `json:"ConnType,omitempty"`
	ConnUUID  string            `json:"ConnUUID,omitempty"`
	SSID      string            `json:"SSID,omitempty"`
	Fields    map[string]string `json:"Fields,omitempty"`
	// firewall
	Table  string `json:"Table,omitempty"`
	Chain  string `json:"Chain,omitempty"`
	Policy string `json:"Policy,omitempty"`
	Rule   string `json:"Rule,omitempty"`
	// raw captures (netplan, nftables)
	Config string `json:"Config,omitempty"`
	Line   int    `json:"Line,omitempty"`
	Raw    string `json:"Raw,omitempty"`
}

// ---- classification --------------------------------------------------------

func classify(rel string) string {
	rel = strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(rel)
	dir := filepath.Base(filepath.Dir(rel))
	switch base {
	case "hosts":
		if dir == "etc" || dir == "." {
			return "hosts"
		}
	case "resolv.conf":
		return "resolv"
	case "nsswitch.conf":
		return "nsswitch"
	case "hosts.allow", "hosts.deny":
		return "tcpwrappers"
	case "interfaces":
		if dir == "network" {
			return "interfaces"
		}
	case "nftables.conf":
		return "nftables"
	case "rules.v4", "rules.v6", "iptables", "ip6tables":
		return "iptables"
	}
	switch {
	case strings.HasSuffix(base, ".nmconnection"):
		return "nmconnection"
	case dir == "interfaces.d":
		return "interfaces"
	case (dir == "network" || dir == "networkd") &&
		(strings.HasSuffix(base, ".network") || strings.HasSuffix(base, ".netdev") || strings.HasSuffix(base, ".link")):
		return "networkd"
	case dir == "netplan" && (strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")):
		return "netplan"
	}
	return ""
}

// ---- parsers ---------------------------------------------------------------

func lineScanner(rd io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return sc
}

// parseHosts: one hosts_entry per line — address then names verbatim.
func parseHosts(rd io.Reader, w *record.Writer) (int, error) {
	sc := lineScanner(rd)
	emitted, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		rec := &netRecord{Line: lineNo}
		rec.RecordType = "hosts_entry"
		rec.IPAddress = f[0]
		if len(f) > 1 {
			rec.Hostnames = f[1:]
		}
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

// parseResolv: one resolv_entry per directive line.
func parseResolv(rd io.Reader, w *record.Writer) (int, error) {
	sc := lineScanner(rd)
	emitted, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, _ := strings.Cut(line, " ")
		rec := &netRecord{Line: lineNo}
		rec.RecordType = "resolv_entry"
		rec.Directive = k
		rec.Value = strings.TrimSpace(v)
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

// parseNsswitch: one nsswitch_entry per database line.
func parseNsswitch(rd io.Reader, w *record.Writer) (int, error) {
	sc := lineScanner(rd)
	emitted, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		db, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		rec := &netRecord{Line: lineNo}
		rec.RecordType = "nsswitch_entry"
		rec.Database = strings.TrimSpace(db)
		rec.Sources = strings.Fields(rest)
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

// parseTCPWrappers: one tcpwrappers_entry per rule (daemons : clients [: option]).
func parseTCPWrappers(rd io.Reader, w *record.Writer) (int, error) {
	sc := lineScanner(rd)
	emitted, lineNo := 0, 0
	pending := ""
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		if pending != "" {
			line = pending + " " + strings.TrimSpace(line)
			pending = ""
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, "\\") {
			pending = strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
			continue
		}
		parts := strings.SplitN(trimmed, ":", 3)
		rec := &netRecord{Line: lineNo, Raw: trimmed}
		rec.RecordType = "tcpwrappers_entry"
		if len(parts) >= 2 {
			rec.Daemons = strings.TrimSpace(parts[0])
			rec.Clients = strings.TrimSpace(parts[1])
			if len(parts) == 3 {
				rec.Option = strings.TrimSpace(parts[2])
			}
		}
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

// parseInterfaces: ifupdown stanzas — one interface_profile per `iface`,
// with its indented option lines; auto/allow-hotplug recorded as directives.
func parseInterfaces(rd io.Reader, w *record.Writer) (int, error) {
	sc := lineScanner(rd)
	emitted, lineNo := 0, 0
	var cur *netRecord
	flush := func() error {
		if cur == nil {
			return nil
		}
		err := w.Write(cur)
		if err == nil {
			emitted++
		}
		cur = nil
		return err
	}
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		switch f[0] {
		case "iface":
			if err := flush(); err != nil {
				return emitted, err
			}
			cur = &netRecord{Line: lineNo, Fields: map[string]string{}}
			cur.RecordType = "interface_profile"
			if len(f) > 1 {
				cur.Interface = f[1]
			}
			if len(f) > 2 {
				cur.Family = f[2]
			}
			if len(f) > 3 {
				cur.Method = f[3]
			}
		case "auto", "allow-hotplug", "source", "source-directory", "mapping":
			if err := flush(); err != nil {
				return emitted, err
			}
			rec := &netRecord{Line: lineNo}
			rec.RecordType = "interfaces_directive"
			rec.Directive = f[0]
			rec.Value = strings.Join(f[1:], " ")
			if err := w.Write(rec); err != nil {
				return emitted, err
			}
			emitted++
		default:
			if cur != nil && len(f) > 1 {
				cur.Fields[f[0]] = strings.Join(f[1:], " ")
			}
		}
	}
	if err := sc.Err(); err != nil {
		return emitted, err
	}
	return emitted, flush()
}

// parseINIProfile handles networkd (.network/.netdev/.link) and
// NetworkManager .nmconnection files: one record per file, sections
// flattened to "Section.Key" in Fields, the identity keys lifted.
func parseINIProfile(rd io.Reader, family string, w *record.Writer) (int, error) {
	sc := lineScanner(rd)
	rec := &netRecord{Fields: map[string]string{}}
	rec.RecordType = family + "_profile"
	section := ""
	saw := false
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			saw = true
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		lk := strings.ToLower(section + "." + k)
		switch lk {
		case "connection.id":
			rec.Name = v
		case "connection.type":
			rec.ConnType = v
		case "connection.uuid":
			rec.ConnUUID = v
		case "wifi.ssid", "802-11-wireless.ssid":
			rec.SSID = v
		case "match.name":
			rec.Interface = v
		default:
			rec.Fields[section+"."+k] = v
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if !saw {
		return 0, fmt.Errorf("no [Section] headers: not a %s profile", family)
	}
	if len(rec.Fields) == 0 {
		rec.Fields = nil
	}
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

// parseIptables reads iptables-save output: table context (*filter), chain
// policies (:INPUT ACCEPT [0:0]) and rules (-A CHAIN ...), verbatim.
func parseIptables(rd io.Reader, w *record.Writer) (int, error) {
	sc := lineScanner(rd)
	emitted, lineNo := 0, 0
	table := ""
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") || line == "COMMIT" {
			continue
		}
		rec := &netRecord{Line: lineNo, Table: table}
		switch {
		case strings.HasPrefix(line, "*"):
			table = line[1:]
			continue
		case strings.HasPrefix(line, ":"):
			f := strings.Fields(line[1:])
			rec.RecordType = "iptables_chain"
			if len(f) > 0 {
				rec.Chain = f[0]
			}
			if len(f) > 1 {
				rec.Policy = f[1]
			}
		default:
			rec.RecordType = "iptables_rule"
			rec.Rule = line
			f := strings.Fields(line)
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "-A" || f[i] == "-I" {
					rec.Chain = f[i+1]
					break
				}
			}
		}
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

// parseRawConfig captures a config file this tool does not decode line by
// line (netplan YAML, nftables.conf) verbatim, capped, as one record — the
// evidence surfaces; field-level decoding is a later map or tool.
func parseRawConfig(rd io.Reader, family string, w *record.Writer) (int, error) {
	const maxCfg = 64 * 1024
	b, err := io.ReadAll(io.LimitReader(rd, maxCfg+1))
	if err != nil {
		return 0, err
	}
	rec := &netRecord{}
	rec.RecordType = family + "_config"
	if len(b) > maxCfg {
		rec.Config = string(b[:maxCfg]) + "\n# [gonetwork: truncated at 64KiB]"
	} else {
		rec.Config = string(b)
	}
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

func parseByFamily(rd io.Reader, family string, w *record.Writer) (int, error) {
	switch family {
	case "hosts":
		return parseHosts(rd, w)
	case "resolv":
		return parseResolv(rd, w)
	case "nsswitch":
		return parseNsswitch(rd, w)
	case "tcpwrappers":
		return parseTCPWrappers(rd, w)
	case "interfaces":
		return parseInterfaces(rd, w)
	case "networkd", "nmconnection":
		return parseINIProfile(rd, family, w)
	case "iptables":
		return parseIptables(rd, w)
	case "netplan", "nftables":
		return parseRawConfig(rd, family, w)
	}
	return 0, fmt.Errorf("unknown family %q", family)
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "gonetwork",
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
		file  = flag.String("f", "", "parse one network-config file (family from its path)")
		dir   = flag.String("d", "", "recurse a directory")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gonetwork                          (env-driven batch mode)\n"+
			"       gonetwork -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		family := classify(rel)
		if family == "" {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gonetwork: %s: not a gonetwork file, skipped\n", path)
			}
			return
		}
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "gonetwork", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseByFamily(f, family, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gonetwork: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return classify(rel) != "" })
		if err != nil {
			fmt.Fprintf(os.Stderr, "gonetwork: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "gonetwork: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
