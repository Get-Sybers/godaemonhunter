// goauditd — Linux audit log parser for the DX_DFIR pipeline
// (docs/linux §4). Finds audit.log files (rotations and gzip included)
// under the input tree and emits ONE RECORD PER EVENT: consecutive records
// sharing an `audit(sec.msec:serial)` id — SYSCALL + EXECVE + CWD + PATH +
// PROCTITLE and the USER_* families — are coalesced, hex-encoded fields are
// decoded, and execve argv is reassembled in order.
//
// Rules (docs/linux §4.1): everything stays native — the record types, the
// syscall number (a name is added for the x86_64 table as a rendering),
// numeric uids verbatim (resolution is enrichment, byakugan's). The audit
// id is the record's identity field, carried never minted. The kernel's
// milliseconds land in EventTime.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOAUDITD_* environment. The argv flags are the
// debug pass-through:
//
//	goauditd -f FILE | -d DIR [-q]
package auditd

import (
	"bufio"
	"encoding/hex"
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
	"github.com/Get-Sybers/gopinfo/knowledge"
	"github.com/Get-Sybers/gopinfo/record"
	"github.com/Get-Sybers/gopinfo/tstamp"
)

// pathEntry is one PATH record of an event.
type pathEntry struct {
	Name     string `json:"Name,omitempty"`
	Nametype string `json:"Nametype,omitempty"`
	Inode    string `json:"Inode,omitempty"`
	Mode     string `json:"Mode,omitempty"`
}

// auditEvent is one coalesced event (RecordType "auditd_event").
type auditEvent struct {
	record.Envelope
	AuditID     string            `json:"AuditID"`
	Node        string            `json:"Node,omitempty"`
	Types       []string          `json:"Types"`
	Syscall     string            `json:"Syscall,omitempty"`
	SyscallName string            `json:"SyscallName,omitempty"`
	Arch        string            `json:"Arch,omitempty"`
	Success     string            `json:"Success,omitempty"`
	Exit        string            `json:"Exit,omitempty"`
	PID         string            `json:"PID,omitempty"`
	PPID        string            `json:"PPID,omitempty"`
	UID         string            `json:"UID,omitempty"`
	UIDName     string            `json:"UIDName,omitempty"`
	AUID        string            `json:"AUID,omitempty"`
	AUIDName    string            `json:"AUIDName,omitempty"`
	EUID        string            `json:"EUID,omitempty"`
	EUIDName    string            `json:"EUIDName,omitempty"`
	GID         string            `json:"GID,omitempty"`
	GIDName     string            `json:"GIDName,omitempty"`
	SES         string            `json:"SES,omitempty"`
	TTY         string            `json:"TTY,omitempty"`
	Comm        string            `json:"Comm,omitempty"`
	Exe         string            `json:"Exe,omitempty"`
	Key         string            `json:"Key,omitempty"`
	Argv        []string          `json:"Argv,omitempty"`
	Cwd         string            `json:"Cwd,omitempty"`
	Paths       []pathEntry       `json:"Paths,omitempty"`
	Proctitle   string            `json:"Proctitle,omitempty"`
	Fields      map[string]string `json:"Fields,omitempty"`
}

// syscallNamesX8664 renders common x86_64 syscall numbers (arch c000003e);
// unknown numbers and other arches keep the number only — native verbatim.
var syscallNamesX8664 = map[string]string{
	"0": "read", "1": "write", "2": "open", "3": "close", "41": "socket",
	"42": "connect", "43": "accept", "49": "bind", "56": "clone",
	"57": "fork", "58": "vfork", "59": "execve", "62": "kill",
	"76": "truncate", "80": "chdir", "82": "rename", "83": "mkdir",
	"84": "rmdir", "85": "creat", "86": "link", "87": "unlink",
	"88": "symlink", "90": "chmod", "92": "chown", "101": "ptrace",
	"105": "setuid", "106": "setgid", "117": "setresuid", "157": "prctl",
	"165": "mount", "175": "init_module", "176": "delete_module",
	"257": "openat", "263": "unlinkat", "268": "fchmodat",
	"313": "finit_module", "316": "renameat2", "319": "memfd_create",
	"322": "execveat", "437": "openat2",
}

// ---- record parsing --------------------------------------------------------

var headRe = regexp.MustCompile(`^(?:node=(\S+) )?type=(\S+) msg=audit\((\d+)\.(\d{1,3}):(\d+)\):\s*(.*)$`)

// parseKV tokenises an audit record body: key=value pairs where value is a
// 'single-quoted' or "double-quoted" string or a bare token.
func parseKV(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			break
		}
		key := s[i : i+eq]
		if sp := strings.LastIndexAny(key, " \t"); sp >= 0 {
			key = key[sp+1:]
			i += sp + 1
			eq -= sp + 1
		}
		i += eq + 1
		if i >= len(s) {
			out[key] = ""
			break
		}
		var val string
		switch s[i] {
		case '"', '\'':
			q := s[i]
			end := strings.IndexByte(s[i+1:], q)
			if end < 0 {
				val = s[i+1:]
				i = len(s)
			} else {
				val = s[i+1 : i+1+end]
				i += end + 2
			}
		default:
			end := strings.IndexAny(s[i:], " \t")
			if end < 0 {
				val = s[i:]
				i = len(s)
			} else {
				val = s[i : i+end]
				i += end
			}
		}
		out[key] = val
	}
	return out
}

// unhex decodes an audit hex-encoded value (unquoted, even length, all hex);
// audit uses it for values holding spaces or control bytes. NUL separators
// (proctitle/execve argv) become spaces.
func unhex(s string) (string, bool) {
	if len(s) < 2 || len(s)%2 != 0 {
		return s, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return s, false
	}
	return strings.ReplaceAll(string(b), "\x00", " "), true
}

// maybeHex decodes when the value looks hex-encoded, else returns verbatim.
func maybeHex(s string) string {
	if isHexish(s) {
		if d, ok := unhex(s); ok {
			return d
		}
	}
	return s
}

func isHexish(s string) bool {
	if len(s) < 4 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// extracted are the SYSCALL keys lifted into named fields; the rest go to
// the Fields map.
var extracted = map[string]bool{
	"arch": true, "syscall": true, "success": true, "exit": true,
	"pid": true, "ppid": true, "uid": true, "auid": true, "euid": true,
	"gid": true, "ses": true, "tty": true, "comm": true, "exe": true,
	"key": true,
}

// apply folds one record's kv into the event.
func (e *auditEvent) apply(rtype string, kv map[string]string) {
	switch rtype {
	case "SYSCALL":
		e.Arch = kv["arch"]
		e.Syscall = kv["syscall"]
		if e.Arch == "c000003e" {
			e.SyscallName = syscallNamesX8664[e.Syscall]
		}
		e.Success, e.Exit = kv["success"], kv["exit"]
		e.PID, e.PPID = kv["pid"], kv["ppid"]
		e.UID, e.AUID, e.EUID, e.GID = kv["uid"], kv["auid"], kv["euid"], kv["gid"]
		e.SES, e.TTY = kv["ses"], kv["tty"]
		e.Comm, e.Exe = maybeHex(kv["comm"]), kv["exe"]
		if k := kv["key"]; k != "(null)" {
			e.Key = maybeHex(k)
		}
		for k, v := range kv {
			if !extracted[k] {
				e.field(k, v)
			}
		}
	case "EXECVE":
		argc := 0
		if n, err := strconv.Atoi(kv["argc"]); err == nil {
			argc = n
		}
		for i := 0; ; i++ {
			v, ok := kv["a"+strconv.Itoa(i)]
			if !ok {
				if argc == 0 || i >= argc {
					break
				}
				continue
			}
			e.Argv = append(e.Argv, maybeHex(v))
		}
	case "CWD":
		e.Cwd = maybeHex(kv["cwd"])
	case "PATH":
		e.Paths = append(e.Paths, pathEntry{
			Name: maybeHex(kv["name"]), Nametype: kv["nametype"],
			Inode: kv["inode"], Mode: kv["mode"],
		})
	case "PROCTITLE":
		e.Proctitle = maybeHex(kv["proctitle"])
	case "EOE":
	default:
		for k, v := range kv {
			e.field(k, maybeHex(v))
		}
	}
}

func (e *auditEvent) field(k, v string) {
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	if _, dup := e.Fields[k]; !dup {
		e.Fields[k] = v
	}
}

// parseAudit streams audit.log lines, coalescing by audit id.
// resolve fills the knowledge-store name fields beside the native
// numeric ids (decision 14: fill-only, image-self-knowledge).
func (e *auditEvent) resolve(ks *knowledge.Store) {
	e.UIDName = ks.Username(e.UID)
	e.AUIDName = ks.Username(e.AUID)
	e.EUIDName = ks.Username(e.EUID)
	e.GIDName = ks.Groupname(e.GID)
}

func parseAudit(rd io.Reader, ks *knowledge.Store, w *record.Writer, warnf func(string, ...interface{})) (int, error) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	emitted, unmatched, lines := 0, 0, 0
	var cur *auditEvent
	const maxTypesPerEvent = 512

	flush := func() error {
		if cur == nil {
			return nil
		}
		cur.resolve(ks)
		err := w.Write(cur)
		cur = nil
		if err == nil {
			emitted++
		}
		return err
	}

	for sc.Scan() {
		lines++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := headRe.FindStringSubmatch(line)
		if m == nil {
			unmatched++
			continue
		}
		node, rtype := m[1], m[2]
		id := m[3] + "." + m[4] + ":" + m[5]
		if cur == nil || cur.AuditID != id || len(cur.Types) >= maxTypesPerEvent {
			if err := flush(); err != nil {
				return emitted, err
			}
			cur = &auditEvent{AuditID: id, Node: node}
			cur.RecordType = "auditd_event"
			sec, _ := strconv.ParseInt(m[3], 10, 64)
			ms, _ := strconv.ParseInt(m[4], 10, 64)
			cur.EventTime = tstamp.Unix(sec, ms*int64(1e6))
			cur.TimeKind = "event"
		}
		cur.Types = append(cur.Types, rtype)
		cur.apply(rtype, parseKV(m[6]))
	}
	if err := sc.Err(); err != nil {
		return emitted, err
	}
	if err := flush(); err != nil {
		return emitted, err
	}
	if emitted == 0 && unmatched > 0 {
		return 0, fmt.Errorf("no audit records parsed (%d non-audit lines)", unmatched)
	}
	if unmatched > 0 {
		warnf("%d non-audit lines skipped", unmatched)
	}
	return emitted, nil
}

func isAuditFile(rel string) bool {
	return discover.Rotated(strings.ToLower(filepath.Base(rel)), "audit.log")
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "goauditd",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			return isAuditFile(rel)
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		f, err := discover.OpenAuto(item)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return parseAudit(f, cfg.Knowledge(), w, func(format string, args ...interface{}) {
			cfg.Logf(batch.LogWarn, item+": "+format, args...)
		})
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one audit.log file")
		dir   = flag.String("d", "", "recurse a directory for audit.log files")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: goauditd                           (env-driven batch mode)\n"+
			"       goauditd -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	warnf := func(f string, a ...interface{}) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "goauditd: "+f+"\n", a...)
		}
	}
	failed := 0
	one := func(path, rel string) {
		f, err := discover.OpenAuto(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "goauditd", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseAudit(f, nil, w, warnf)
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
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return isAuditFile(rel) })
		if err != nil {
			fmt.Fprintf(os.Stderr, "goauditd: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "goauditd: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
