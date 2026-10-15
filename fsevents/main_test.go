package fsevents

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Get-Sybers/gopinfo/record"
)

// rec builds one DLS record body: path\0 + id(u64) + flags(u32) + (node(u64)
// for a 2SLD page).
func rec(path string, id uint64, flags uint32, node uint64, v2 bool) []byte {
	b := append([]byte(path), 0)
	b = binary.LittleEndian.AppendUint64(b, id)
	b = binary.LittleEndian.AppendUint32(b, flags)
	if v2 {
		b = binary.LittleEndian.AppendUint64(b, node)
	}
	return b
}

// page builds a DLS page: magic + unknown(u32) + pageSize(u32, incl. the
// 12-byte header) + body.
func page(magic string, body []byte) []byte {
	p := []byte(magic)
	p = binary.LittleEndian.AppendUint32(p, 0)
	p = binary.LittleEndian.AppendUint32(p, uint32(12+len(body)))
	return append(p, body...)
}

func parseAll(t *testing.T, dls []byte) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseDLS(bytes.NewReader(dls), w); err != nil {
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

func TestParseDLS(t *testing.T) {
	// A 2SLD page (two real records + an empty-path padding record) followed by
	// a 1SLD page — covers both versions, multi-page walking and padding skip.
	body2 := append(rec("Users/gl/a.txt", 100, 0x01000000, 999, true),
		rec("Users/gl/b.txt", 101, 0x10000000, 1000, true)...)
	body2 = append(body2, rec("", 102, 0, 0, true)...) // padding -> skipped
	body1 := rec(".fseventsd/sl-compat", 58278, 0x01000000, 0, false)
	dls := append(page("2SLD", body2), page("1SLD", body1)...)

	recs := parseAll(t, dls)
	if len(recs) != 3 {
		t.Fatalf("records: %d (want 3; empty-path padding must be skipped)", len(recs))
	}
	r0 := recs[0]
	if r0["RecordType"] != "fsevent" || r0["Path"] != "Users/gl/a.txt" ||
		r0["EventID"] != float64(100) || r0["Flags"] != float64(0x01000000) || r0["NodeID"] != float64(999) {
		t.Fatalf("rec0: %v", r0)
	}
	// fsevents carry an ordering counter, not a clock — no EventTime/TimeKind.
	if _, ok := r0["EventTime"]; ok {
		t.Fatalf("fsevent unexpectedly has EventTime: %v", r0)
	}
	// The 1SLD record (last) decodes without a NodeID.
	last := recs[2]
	if last["Path"] != ".fseventsd/sl-compat" || last["EventID"] != float64(58278) {
		t.Fatalf("1SLD rec: %v", last)
	}
	if _, ok := last["NodeID"]; ok {
		t.Fatalf("1SLD record should carry no NodeID: %v", last)
	}
}

// A page whose declared size overruns the buffer (a truncated log) is parsed to
// the end of what is present, not failed.
func TestParseDLSTruncated(t *testing.T) {
	full := page("2SLD", rec("a/b", 1, 0x01000000, 2, true))
	recs := parseAll(t, full[:len(full)-4]) // lop off the node's last 4 bytes
	if len(recs) != 0 {
		t.Fatalf("truncated tail record should be dropped, got %d", len(recs))
	}
}

func TestIsFseventsLog(t *testing.T) {
	for _, p := range []string{".fseventsd/0000000000005001", "foo/.fseventsd/abcd"} {
		if !isFseventsLog(p) {
			t.Errorf("should match: %q", p)
		}
	}
	for _, p := range []string{".fseventsd/fseventsd-uuid", ".fseventsd/no_log", "var/log/syslog", "Users/gl/file"} {
		if isFseventsLog(p) {
			t.Errorf("should not match: %q", p)
		}
	}
}
