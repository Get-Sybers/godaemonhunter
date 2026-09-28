package wtmp

// main_test.go proves the pure parsing over Go-generated fixtures (no binary
// blobs committed): struct-utmp records, the lastlog table, family
// classification, and the batch binding end-to-end through pinfo/batch.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/get-sybers/gopinfo/batch"
	"github.com/get-sybers/gopinfo/record"
)

// mkUtmp builds one 384-byte glibc utmp record.
func mkUtmp(ut int16, pid int32, line, id, user, host string, ip net.IP, sec, usec int32) []byte {
	b := make([]byte, utmpRecLen)
	binary.LittleEndian.PutUint16(b[0:2], uint16(ut))
	binary.LittleEndian.PutUint32(b[4:8], uint32(pid))
	copy(b[8:40], line)
	copy(b[40:44], id)
	copy(b[44:76], user)
	copy(b[76:332], host)
	binary.LittleEndian.PutUint32(b[336:340], 7)
	binary.LittleEndian.PutUint32(b[340:344], uint32(sec))
	binary.LittleEndian.PutUint32(b[344:348], uint32(usec))
	if ip4 := ip.To4(); ip4 != nil {
		copy(b[348:352], ip4)
	} else if ip != nil {
		copy(b[348:364], ip.To16())
	}
	return b
}

func mkLastlog(slots map[uint32][3]string) []byte { // uid -> {secStr,line,host}
	max := uint32(0)
	for uid := range slots {
		if uid > max {
			max = uid
		}
	}
	b := make([]byte, (max+1)*lastlogLen)
	for uid, s := range slots {
		off := uid * lastlogLen
		var sec int64
		if s[0] != "" {
			sec = mustAtoi(s[0])
		}
		binary.LittleEndian.PutUint32(b[off:off+4], uint32(sec))
		copy(b[off+4:off+36], s[1])
		copy(b[off+36:off+292], s[2])
	}
	return b
}

func mustAtoi(s string) int64 {
	var n int64
	for _, c := range s {
		n = n*10 + int64(c-'0')
	}
	return n
}

func collect(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad record line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func newJSONWriter(t *testing.T) (*record.Writer, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return record.NewWriter(&buf), &buf
}

func nowarn(string, ...interface{}) {}

func TestParseUtmp(t *testing.T) {
	var raw bytes.Buffer
	raw.Write(mkUtmp(7, 4242, "pts/0", "ts/0", "alice", "198.51.100.7", net.ParseIP("198.51.100.7"), 1767225600, 481000))
	raw.Write(mkUtmp(0, 0, "", "", "", "", nil, 0, 0)) // EMPTY — skipped
	raw.Write(mkUtmp(8, 4242, "pts/0", "ts/0", "", "", nil, 1767229200, 0))
	raw.Write(mkUtmp(6, 900, "ttyS0", "", "LOGIN", "2001:db8::1", net.ParseIP("2001:db8::1"), 1767230000, 0))

	w, buf := newJSONWriter(t)
	n, err := parseUtmp(&raw, "wtmp", w, nowarn)
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	w.Flush()
	recs := collect(t, buf)
	if len(recs) != 3 {
		t.Fatalf("records: %d", len(recs))
	}
	login := recs[0]
	if login["Username"] != "alice" || login["Terminal"] != "pts/0" ||
		login["IPAddress"] != "198.51.100.7" || login["LoginType"] != float64(7) ||
		login["LoginTypeName"] != "USER_PROCESS" || login["Source"] != "wtmp" ||
		login["PID"] != float64(4242) || login["RecordType"] != "utmp" {
		t.Fatalf("login row: %v", login)
	}
	if login["EventTime"] != "2026-01-01T00:00:00.481000Z" {
		t.Fatalf("EventTime: %v", login["EventTime"])
	}
	logout := recs[1]
	if logout["LoginType"] != float64(8) || logout["Username"] != nil && logout["Username"] != "" {
		t.Fatalf("logout row: %v", logout)
	}
	if recs[2]["IPAddress"] != "2001:db8::1" {
		t.Fatalf("ipv6 row: %v", recs[2])
	}
}

func TestParseUtmpRejectsGarbage(t *testing.T) {
	w, _ := newJSONWriter(t)
	if _, err := parseUtmp(bytes.NewReader(bytes.Repeat([]byte{0xAB}, utmpRecLen*20)), "wtmp", w, nowarn); err == nil {
		t.Fatal("garbage accepted as utmp")
	}
	if _, err := parseUtmp(bytes.NewReader([]byte{1, 2, 3}), "wtmp", w, nowarn); err == nil {
		t.Fatal("short file accepted")
	}
}

func TestParseUtmpTruncatedTail(t *testing.T) {
	var raw bytes.Buffer
	raw.Write(mkUtmp(7, 1, "pts/1", "", "bob", "", nil, 1767225600, 0))
	raw.Write([]byte{0x07, 0x00, 0x01}) // truncated second record
	w, _ := newJSONWriter(t)
	n, err := parseUtmp(&raw, "wtmp", w, nowarn)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestParseLastlog(t *testing.T) {
	raw := mkLastlog(map[uint32][3]string{
		0:    {"1767225600", "tty1", ""},
		1000: {"1767229200", "pts/0", "workstation.example"},
	})
	w, buf := newJSONWriter(t)
	n, err := parseLastlog(bytes.NewReader(raw), nil, w, nowarn)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	w.Flush()
	recs := collect(t, buf)
	if recs[0]["UID"] != float64(0) || recs[0]["Terminal"] != "tty1" {
		t.Fatalf("root row: %v", recs[0])
	}
	if recs[1]["UID"] != float64(1000) || recs[1]["Hostname"] != "workstation.example" ||
		recs[1]["TimeKind"] != "last_login" {
		t.Fatalf("user row: %v", recs[1])
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"wtmp": "wtmp", "wtmp.1": "wtmp", "wtmp.1.gz": "wtmp",
		"btmp": "btmp", "utmp": "utmp", "lastlog": "lastlog",
		"wtmpx": "", "utmpx": "utmpx", "syslog": "", "lastlog2json": "",
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBatchEndToEnd(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(in, "var/log"), 0o755)
	os.WriteFile(filepath.Join(in, "var/log/wtmp"),
		mkUtmp(7, 1, "pts/0", "", "alice", "", nil, 1767225600, 0), 0o644)
	os.WriteFile(filepath.Join(in, "var/log/lastlog"),
		mkLastlog(map[uint32][3]string{0: {"1767225600", "tty1", ""}}), 0o644)
	os.WriteFile(filepath.Join(in, "var/log/syslog"), []byte("not ours"), 0o644)

	env := map[string]string{
		"GOWTMP_INPUT_DIR": in, "GOWTMP_OUT_DIR": out, "GOWTMP_WORK_DIR": t.TempDir(),
	}
	var stdout bytes.Buffer
	code := batch.Run(Tool, batch.Options{Version: "test"},
		func(k string) string { return env[k] }, &stdout)
	if code != 0 {
		t.Fatalf("exit %d, stdout %s", code, stdout.String())
	}
	var sum batch.Summary
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Inputs != 2 || sum.Processed != 2 || sum.Records != 2 {
		t.Fatalf("summary: %+v", sum)
	}
	b, err := os.ReadFile(filepath.Join(out, "var_log_wtmp", "gowtmp.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(b), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["Tool"] != "gowtmp" || rec["SourceFilename"] != "var/log/wtmp" || rec["Username"] != "alice" {
		t.Fatalf("record: %v", rec)
	}
}

// TestUtmpx reads the macOS 628-byte layout: a SIGNATURE head record, a
// BOOT_TIME and a USER_PROCESS with its 32-bit timeval at offset 300.
func TestUtmpx(t *testing.T) {
	rec := func(user, id, line string, pid uint32, typ uint16, sec, usec uint32, host string) []byte {
		b := make([]byte, utmpxRecLen)
		copy(b[0:], user)
		copy(b[256:], id)
		copy(b[260:], line)
		binary.LittleEndian.PutUint32(b[292:], pid)
		binary.LittleEndian.PutUint16(b[296:], typ)
		binary.LittleEndian.PutUint32(b[300:], sec)
		binary.LittleEndian.PutUint32(b[304:], usec)
		copy(b[308:], host)
		return b
	}
	var file []byte
	file = append(file, rec("utmpx-1.00", "", "", 0, utmpxSigType, 0, 0, "")...)
	file = append(file, rec("", "", "", 1, 2, 0x660bf500, 0, "")...)
	file = append(file, rec("gl", "/\x00\x01\x01", "console", 140, 7, 0x660bf527, 976757, "")...)
	file = append(file, rec("gl", "s000", "ttys000", 512, 8, 0x660bf600, 0, "10.0.0.5")...)
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	n, err := parseStream(bytes.NewReader(file), "utmpx", nil, w, func(string, ...interface{}) {})
	w.Flush()
	if err != nil || n != 3 {
		t.Fatalf("utmpx: %d records, %v", n, err)
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	var boot, login, logout map[string]any
	json.Unmarshal(lines[0], &boot)
	json.Unmarshal(lines[1], &login)
	json.Unmarshal(lines[2], &logout)
	if boot["LoginTypeName"] != "BOOT_TIME" || boot["EventTime"] != "2024-04-02T12:07:28.000000Z" {
		t.Fatalf("boot: %v", boot)
	}
	if login["Username"] != "gl" || login["Terminal"] != "console" || login["PID"] != float64(140) || login["LoginTypeName"] != "USER_PROCESS" || login["EventTime"] != "2024-04-02T12:08:07.976757Z" {
		t.Fatalf("login: %v", login)
	}
	if logout["LoginTypeName"] != "DEAD_PROCESS" || logout["Hostname"] != "10.0.0.5" || logout["TerminalID"] != "s000" || logout["Source"] != "utmpx" {
		t.Fatalf("logout: %v", logout)
	}
	if _, err := parseStream(bytes.NewReader(file[:100]), "utmpx", nil, record.NewWriter(&buf), func(string, ...interface{}) {}); err == nil {
		t.Fatal("a short file must error")
	}
}
