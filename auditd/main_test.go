package auditd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Get-Sybers/gopinfo/knowledge"
	"github.com/Get-Sybers/gopinfo/record"
)

// a benign execve event (ls -la in /home/alice) plus a service start.
const fixture = `type=SYSCALL msg=audit(1767225600.123:42): arch=c000003e syscall=59 success=yes exit=0 ppid=1200 pid=1201 auid=1000 uid=1000 gid=1000 euid=1000 ses=3 tty=pts0 comm="ls" exe="/usr/bin/ls" key="exec_log"
type=EXECVE msg=audit(1767225600.123:42): argc=2 a0="ls" a1=2D6C61
type=CWD msg=audit(1767225600.123:42): cwd="/home/alice"
type=PATH msg=audit(1767225600.123:42): item=0 name="/usr/bin/ls" inode=131204 mode=0100755 nametype=NORMAL
type=PROCTITLE msg=audit(1767225600.123:42): proctitle=6C73002D6C61
type=EOE msg=audit(1767225600.123:42):
type=SERVICE_START msg=audit(1767225700.000:43): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=nginx comm="systemd" exe="/usr/lib/systemd/systemd" res=success'
`

func parse(t *testing.T, content string) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseAudit(strings.NewReader(content), nil, w, func(string, ...interface{}) {}); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		json.Unmarshal([]byte(l), &m)
		out = append(out, m)
	}
	return out
}

func TestCoalescedExecve(t *testing.T) {
	recs := parse(t, fixture)
	if len(recs) != 2 {
		t.Fatalf("events: %d", len(recs))
	}
	e := recs[0]
	if e["AuditID"] != "1767225600.123:42" || e["EventTime"] != "2026-01-01T00:00:00.123000Z" {
		t.Fatalf("identity/time: %v", e)
	}
	types := e["Types"].([]any)
	if len(types) != 6 || types[0] != "SYSCALL" || types[5] != "EOE" {
		t.Fatalf("types: %v", types)
	}
	if e["Syscall"] != "59" || e["SyscallName"] != "execve" || e["Success"] != "yes" ||
		e["PID"] != "1201" || e["UID"] != "1000" || e["Comm"] != "ls" ||
		e["Exe"] != "/usr/bin/ls" || e["Key"] != "exec_log" {
		t.Fatalf("syscall fields: %v", e)
	}
	argv := e["Argv"].([]any)
	if len(argv) != 2 || argv[0] != "ls" || argv[1] != "-la" { // a1 was hex 2D6C61
		t.Fatalf("argv: %v", argv)
	}
	if e["Cwd"] != "/home/alice" || e["Proctitle"] != "ls -la" {
		t.Fatalf("cwd/proctitle: %v", e)
	}
	paths := e["Paths"].([]any)
	p0 := paths[0].(map[string]any)
	if p0["Name"] != "/usr/bin/ls" || p0["Nametype"] != "NORMAL" || p0["Inode"] != "131204" {
		t.Fatalf("paths: %v", paths)
	}

	s := recs[1]
	if s["AuditID"] != "1767225700.000:43" || s["Syscall"] != nil {
		t.Fatalf("second event: %v", s)
	}
	fields := s["Fields"].(map[string]any)
	if !strings.Contains(fields["msg"].(string), "unit=nginx") {
		t.Fatalf("fields: %v", fields)
	}
}

func TestGarbageRejected(t *testing.T) {
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseAudit(strings.NewReader("hello\nworld\n"), nil, w, func(string, ...interface{}) {}); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestParseKVQuoting(t *testing.T) {
	kv, quoted := parseKV(`a="x y" b='p q' c=bare d=`)
	if kv["a"] != "x y" || kv["b"] != "p q" || kv["c"] != "bare" || kv["d"] != "" {
		t.Fatalf("kv: %v", kv)
	}
	if !quoted["a"] || !quoted["b"] || quoted["c"] {
		t.Fatalf("quoted tracking: %v", quoted)
	}
}

// Quote-aware decoding: a BARE hex value whose hex is all decimal digits
// (e.g. proctitle "cat a" = 6361742061, argv "cat" = 636174) still decodes,
// while a QUOTED literal that happens to be all hex-digits (an execve arg
// "1234") stays verbatim. auditd hex-encodes only bare values, so the quote is
// the signal — not a value heuristic that would mis-handle one or the other.
func TestQuoteAwareHexDecode(t *testing.T) {
	const in = "type=SYSCALL msg=audit(7.1:1): arch=c000003e syscall=59 success=yes exit=0 pid=5 comm=\"cat\" key=(null)\n" +
		"type=EXECVE msg=audit(7.1:1): argc=2 a0=636174 a1=\"1234\"\n" +
		"type=PROCTITLE msg=audit(7.1:1): proctitle=6361742061\n" +
		"type=EOE msg=audit(7.1:1):\n"
	recs := parse(t, in)
	if len(recs) != 1 {
		t.Fatalf("events: %d", len(recs))
	}
	e := recs[0]
	if e["Proctitle"] != "cat a" {
		t.Fatalf("all-digit-hex proctitle should decode: %q", e["Proctitle"])
	}
	argv := e["Argv"].([]any)
	if len(argv) != 2 || argv[0] != "cat" || argv[1] != "1234" {
		t.Fatalf("bare-hex a0 should decode, quoted a1 should stay literal: %v", argv)
	}
}

func TestIsAuditFile(t *testing.T) {
	if !isAuditFile("var/log/audit/audit.log") || !isAuditFile("var/log/audit/audit.log.3") {
		t.Fatal("audit files not matched")
	}
	if isAuditFile("var/log/audit/audit.rules") || isAuditFile("var/log/syslog") {
		t.Fatal("non-audit matched")
	}
}

func TestNodePrefix(t *testing.T) {
	recs := parse(t, "node=srv02 type=SYSCALL msg=audit(1767225800.001:44): arch=c000003e syscall=257 success=yes exit=3 pid=99 uid=0 comm=\"cat\" exe=\"/usr/bin/cat\"\nnode=srv02 type=EOE msg=audit(1767225800.001:44):\n")
	if len(recs) != 1 || recs[0]["Node"] != "srv02" || recs[0]["AuditID"] != "1767225800.001:44" ||
		recs[0]["SyscallName"] != "openat" {
		t.Fatalf("node event: %v", recs)
	}
}

func TestKnowledgeResolution(t *testing.T) {
	kd := t.TempDir()
	os.MkdirAll(filepath.Join(kd, "etc_passwd"), 0o755)
	os.WriteFile(filepath.Join(kd, "etc_passwd", "gousers.jsonl"), []byte(
		`{"RecordType":"account","Username":"alice","UID":1000}`+"\n"+
			`{"RecordType":"group","GroupName":"alice","GID":1000}`+"\n"), 0o644)
	ks := knowledge.Load(kd)
	if ks == nil {
		t.Fatal("store not loaded")
	}
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseAudit(strings.NewReader(fixture), ks, w, func(string, ...interface{}) {}); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	var e map[string]any
	json.Unmarshal([]byte(strings.SplitN(strings.TrimSpace(buf.String()), "\n", 2)[0]), &e)
	if e["UID"] != "1000" || e["UIDName"] != "alice" || e["AUIDName"] != "alice" ||
		e["GIDName"] != "alice" || e["EUIDName"] != "alice" {
		t.Fatalf("resolution (native beside resolved): %v", e)
	}
}

// ENRICHED log_format (auditd log_format=ENRICHED) appends interpreted fields
// after an ASCII GS (0x1d). The parser must drop that trailer, keep numeric ids
// verbatim, and never leak a 0x1d into a field key or the audit-rule Key.
func TestEnrichedFormat(t *testing.T) {
	const enriched = "type=SERVICE_STOP msg=audit(1683112130.213:11932): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='unit=scoringbot comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" res=success'\x1dUID=\"root\" AUID=\"unset\"\n" +
		"type=SYSCALL msg=audit(1683112130.100:11000): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd614ce6f0 items=1 ppid=1 pid=1234 auid=4294967295 uid=0 gid=0 ses=4294967295 comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" subj=unconfined key=(null)\x1dARCH=x86_64 SYSCALL=execve AUID=\"unset\" UID=\"root\" GID=\"root\"\n" +
		"type=EOE msg=audit(1683112130.100:11000):\n"
	recs := parse(t, enriched)
	if len(recs) != 2 {
		t.Fatalf("events: %d", len(recs))
	}

	stop := recs[0]
	sf := stop["Fields"].(map[string]any)
	if sf["auid"] != "4294967295" || sf["ses"] != "4294967295" {
		t.Fatalf("SERVICE_STOP numeric ids not verbatim (hex-decoded?): %v", sf)
	}
	for k := range sf {
		if strings.ContainsRune(k, '\x1d') {
			t.Fatalf("field key carries a raw 0x1d: %q", k)
		}
		if k == "UID" || k == "AUID" {
			t.Fatalf("enriched interpreted trailer leaked into Fields: %q", k)
		}
	}

	sys := recs[1]
	if sys["Key"] != nil && sys["Key"] != "" {
		t.Fatalf("audit-rule Key swallowed the enriched trailer: %v", sys["Key"])
	}
	if sys["AUID"] != "4294967295" {
		t.Fatalf("SYSCALL auid not verbatim: %v", sys["AUID"])
	}
	yf, _ := sys["Fields"].(map[string]any)
	for k := range yf {
		if strings.ContainsRune(k, '\x1d') {
			t.Fatalf("SYSCALL field key carries a raw 0x1d: %q", k)
		}
	}
	// a pointer value (all-hex, with letters) in a SYSCALL stays verbatim —
	// SYSCALL never hex-decodes its non-extracted fields.
	if yf["a0"] != "7ffd614ce6f0" {
		t.Fatalf("a0 not verbatim: %v", yf["a0"])
	}
}

// auditd never hex-encodes numeric ids; a plain decimal that happens to be
// all hex-digits and even length must pass through verbatim, not be decoded
// into binary (the isHexish decimal false-positive).
func TestNumericNotHexDecoded(t *testing.T) {
	recs := parse(t, "type=SERVICE_STOP msg=audit(100.1:7): pid=1234 uid=0 auid=4294967295 ses=4294967295\n")
	f := recs[0]["Fields"].(map[string]any)
	if f["pid"] != "1234" || f["auid"] != "4294967295" || f["ses"] != "4294967295" {
		t.Fatalf("numeric fields corrupted: %v", f)
	}
}

// The generic record path decodes only known hex-encoded string fields. A
// BPRM_FCAPS capability mask (pe/pp/old_pe/old_pp) is hex-with-letters but is a
// bitmask auditd never encodes, so it stays verbatim; a USER_CMD cmd is a
// genuinely hex-encoded string and still decodes.
func TestDefaultCaseFieldScoping(t *testing.T) {
	const in = "type=SYSCALL msg=audit(5.1:9): arch=c000003e syscall=59 success=yes exit=0 pid=5 auid=1000 uid=0 comm=\"sudo\" key=(null)\n" +
		"type=BPRM_FCAPS msg=audit(5.1:9): fver=0 fp=0000000000000000 fe=0 old_pp=0000003fffffffff old_pe=0000003fffffffff pp=0000003fffffffff pe=0000003fffffffff\n" +
		"type=EOE msg=audit(5.1:9):\n" +
		"type=USER_CMD msg=audit(6.1:10): pid=7 uid=0 auid=1000 cmd=6C73202D6C61 terminal=pts0 res=success\n"
	recs := parse(t, in)
	if len(recs) != 2 {
		t.Fatalf("events: %d", len(recs))
	}
	cf := recs[0]["Fields"].(map[string]any)
	for _, k := range []string{"pe", "pp", "old_pe", "old_pp"} {
		if cf[k] != "0000003fffffffff" {
			t.Fatalf("capability mask %s not verbatim: %q", k, cf[k])
		}
	}
	for k, v := range cf {
		if s, ok := v.(string); ok && strings.ContainsRune(s, '�') {
			t.Fatalf("capability field %s decoded to binary: %q", k, s)
		}
	}
	uf := recs[1]["Fields"].(map[string]any)
	if uf["cmd"] != "ls -la" { // 6C73202D6C61 -> "ls -la"
		t.Fatalf("USER_CMD cmd not decoded: %q", uf["cmd"])
	}
}
