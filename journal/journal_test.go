package journal

// journal_test.go builds tiny synthetic journal files in memory — regular
// and compact layouts, uncompressed and XZ/LZ4/ZSTD payloads — and proves
// the reader end to end. No binary fixtures are committed.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/get-sybers/gopinfo/record"
	"github.com/klauspost/compress/zstd"
	lz4 "github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
)

type jb struct {
	buf     []byte
	compact bool
}

func newJB(compact bool) *jb { return &jb{buf: make([]byte, 240), compact: compact} }

func (b *jb) align() {
	for len(b.buf)%8 != 0 {
		b.buf = append(b.buf, 0)
	}
}

func (b *jb) objHeader(typ, flags byte, payload int) {
	h := make([]byte, 16)
	h[0], h[1] = typ, flags
	binary.LittleEndian.PutUint64(h[8:16], uint64(16+payload))
	b.buf = append(b.buf, h...)
}

// addData appends a DATA object holding raw (already compressed when flags
// say so) and returns its offset.
func (b *jb) addData(raw []byte, flags byte) uint64 {
	b.align()
	off := uint64(len(b.buf))
	head := 48
	if b.compact {
		head += 8
	}
	b.objHeader(objData, flags, head+len(raw))
	b.buf = append(b.buf, make([]byte, head)...)
	b.buf = append(b.buf, raw...)
	return off
}

func (b *jb) addEntry(seq, rt, mono uint64, dataOffs []uint64) uint64 {
	b.align()
	off := uint64(len(b.buf))
	step := 16
	if b.compact {
		step = 4
	}
	b.objHeader(objEntry, 0, 48+len(dataOffs)*step)
	p := make([]byte, 48)
	le := binary.LittleEndian
	le.PutUint64(p[0:8], seq)
	le.PutUint64(p[8:16], rt)
	le.PutUint64(p[16:24], mono)
	copy(p[24:40], bytes.Repeat([]byte{0xAB}, 16)) // boot id
	b.buf = append(b.buf, p...)
	for _, d := range dataOffs {
		if b.compact {
			item := make([]byte, 4)
			le.PutUint32(item, uint32(d))
			b.buf = append(b.buf, item...)
		} else {
			item := make([]byte, 16)
			le.PutUint64(item[0:8], d)
			b.buf = append(b.buf, item...)
		}
	}
	return off
}

func (b *jb) addEntryArray(next uint64, offs []uint64) uint64 {
	b.align()
	off := uint64(len(b.buf))
	step := 8
	if b.compact {
		step = 4
	}
	b.objHeader(objEntryArray, 0, 8+len(offs)*step)
	p := make([]byte, 8)
	binary.LittleEndian.PutUint64(p, next)
	b.buf = append(b.buf, p...)
	for _, e := range offs {
		if b.compact {
			item := make([]byte, 4)
			binary.LittleEndian.PutUint32(item, uint32(e))
			b.buf = append(b.buf, item...)
		} else {
			item := make([]byte, 8)
			binary.LittleEndian.PutUint64(item, e)
			b.buf = append(b.buf, item...)
		}
	}
	return off
}

func (b *jb) finish(entryArray uint64, nEntries uint64, extraFlags uint32) []byte {
	le := binary.LittleEndian
	copy(b.buf[0:8], journalMagic)
	flags := extraFlags
	if b.compact {
		flags |= fCompact
	}
	le.PutUint32(b.buf[12:16], flags)
	copy(b.buf[40:56], bytes.Repeat([]byte{0xCD}, 16)) // machine id
	le.PutUint64(b.buf[88:96], 240)                    // header_size
	le.PutUint64(b.buf[152:160], nEntries)
	le.PutUint64(b.buf[176:184], entryArray)
	return b.buf
}

func lz4Payload(t *testing.T, s string) []byte {
	t.Helper()
	dst := make([]byte, lz4.CompressBlockBound(len(s)))
	n, err := lz4.CompressBlock([]byte(s), dst, nil)
	if err != nil || n == 0 {
		t.Fatalf("lz4: %v n=%d", err, n)
	}
	out := make([]byte, 8+n)
	binary.LittleEndian.PutUint64(out[0:8], uint64(len(s)))
	copy(out[8:], dst[:n])
	return out
}

func zstdPayload(t *testing.T, s string) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	return enc.EncodeAll([]byte(s), nil)
}

func xzPayload(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	zw.Write([]byte(s))
	zw.Close()
	return buf.Bytes()
}

func decode(t *testing.T, img []byte) []map[string]any {
	t.Helper()
	j, err := openJournal(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	err = j.entryOffsets(func(off uint64) error {
		e, rerr := j.readEntry(off)
		if rerr != nil {
			return rerr
		}
		return w.Write(buildRecord(e, j.hdr.machineID, nil))
	})
	if err != nil {
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

func TestRegularJournal(t *testing.T) {
	b := newJB(false)
	d1 := b.addData([]byte("MESSAGE=service started cleanly"), 0)
	d2 := b.addData([]byte("_PID=1201"), 0)
	d3 := b.addData([]byte("SYSLOG_IDENTIFIER=systemd"), 0)
	d4 := b.addData([]byte("CUSTOM_FIELD=extra value"), 0)
	d5 := b.addData(lz4Payload(t, "_CMDLINE=/usr/bin/daemon --flag"), objFlagLZ4)
	e1 := b.addEntry(7, 1767225600123456, 99, []uint64{d1, d2, d3, d4, d5})
	d6 := b.addData(zstdPayload(t, "MESSAGE=second entry"), objFlagZSTD)
	d7 := b.addData(xzPayload(t, "_COMM=daemon"), objFlagXZ)
	e2 := b.addEntry(8, 1767225601000000, 100, []uint64{d6, d7})
	ea := b.addEntryArray(0, []uint64{e1, e2})
	img := b.finish(ea, 2, fCompressedLZ4|fCompressedZSTD|fCompressedXZ)

	recs := decode(t, img)
	if len(recs) != 2 {
		t.Fatalf("entries: %d", len(recs))
	}
	r := recs[0]
	if r["Message"] != "service started cleanly" || r["PID"] != "1201" ||
		r["Identifier"] != "systemd" || r["Seqnum"] != float64(7) {
		t.Fatalf("entry1: %v", r)
	}
	if r["EventTime"] != "2026-01-01T00:00:00.123456Z" || r["TimeKind"] != "event" {
		t.Fatalf("time: %v", r)
	}
	if r["Cmdline"] != "/usr/bin/daemon --flag" { // lz4 payload
		t.Fatalf("lz4: %v", r)
	}
	if r["Fields"].(map[string]any)["CUSTOM_FIELD"] != "extra value" {
		t.Fatalf("fields: %v", r)
	}
	if r["BootID"] != strings.Repeat("ab", 16) || r["MachineID"] != strings.Repeat("cd", 16) {
		t.Fatalf("ids: %v", r)
	}
	if recs[1]["Message"] != "second entry" || recs[1]["Comm"] != "daemon" {
		t.Fatalf("entry2 (zstd/xz): %v", recs[1])
	}
}

func TestCompactJournal(t *testing.T) {
	b := newJB(true)
	d1 := b.addData([]byte("MESSAGE=compact mode entry"), 0)
	e1 := b.addEntry(1, 1767225600000000, 5, []uint64{d1})
	ea := b.addEntryArray(0, []uint64{e1})
	img := b.finish(ea, 1, 0)
	recs := decode(t, img)
	if len(recs) != 1 || recs[0]["Message"] != "compact mode entry" {
		t.Fatalf("compact: %v", recs)
	}
}

func TestChainedEntryArrays(t *testing.T) {
	b := newJB(false)
	d := b.addData([]byte("MESSAGE=x"), 0)
	e1 := b.addEntry(1, 1, 1, []uint64{d})
	e2 := b.addEntry(2, 2, 2, []uint64{d})
	ea2 := b.addEntryArray(0, []uint64{e2, 0}) // zero slots are skipped
	ea1 := b.addEntryArray(ea2, []uint64{e1})
	img := b.finish(ea1, 2, 0)
	if got := len(decode(t, img)); got != 2 {
		t.Fatalf("chained arrays: %d entries", got)
	}
}

func TestRejectsAndResilience(t *testing.T) {
	if _, err := openJournal(bytes.NewReader([]byte("not a journal")), 13); err == nil {
		t.Fatal("short garbage accepted")
	}
	long := append([]byte("XXXXXXXX"), make([]byte, 300)...)
	if _, err := openJournal(bytes.NewReader(long), int64(len(long))); err == nil {
		t.Fatal("bad signature accepted")
	}
	// a truncated file: the entry array points past the end
	b := newJB(false)
	d := b.addData([]byte("MESSAGE=y"), 0)
	e1 := b.addEntry(1, 1, 1, []uint64{d})
	ea := b.addEntryArray(0, []uint64{e1})
	img := b.finish(ea, 1, 0)
	cut := img[:len(img)-8]
	j, err := openJournal(bytes.NewReader(cut), int64(len(cut)))
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	walkErr := j.entryOffsets(func(off uint64) error { _, e := j.readEntry(off); _ = e; return nil })
	if walkErr == nil {
		t.Log("truncated walk survived (acceptable)")
	}
}

// TestTypedEntries proves the journal is a first-class pathway for the
// typed families: an sshd entry in the journal yields the same
// sshd_event shape the flat auth.log pathway yields, journal fields kept.
func TestTypedEntries(t *testing.T) {
	fp := "SHA256:AbCdEf0123456789AbCdEf0123456789AbCdEf01234"
	b := newJB(false)
	d1 := b.addData([]byte("SYSLOG_IDENTIFIER=sshd"), 0)
	d2 := b.addData([]byte("MESSAGE=Accepted publickey for alice from 198.51.100.7 port 51234 ssh2: ED25519 "+fp), 0)
	d3 := b.addData([]byte("_PID=901"), 0)
	e1 := b.addEntry(1, 1767225600000000, 1, []uint64{d1, d2, d3})
	d4 := b.addData([]byte("_COMM=sudo"), 0)
	d5 := b.addData([]byte("MESSAGE=pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)"), 0)
	e2 := b.addEntry(2, 1767225601000000, 2, []uint64{d4, d5})
	ea := b.addEntryArray(0, []uint64{e1, e2})
	img := b.finish(ea, 2, 0)

	recs := decode(t, img)
	ssh := recs[0]
	if ssh["RecordType"] != "sshd_event" || ssh["SSHEvent"] != "accepted" ||
		ssh["Username"] != "alice" || ssh["IPAddress"] != "198.51.100.7" ||
		ssh["Port"] != float64(51234) || ssh["Fingerprint"] != fp {
		t.Fatalf("journal sshd: %v", ssh)
	}
	// the journal fields ride along untouched
	if ssh["Identifier"] != "sshd" || ssh["PID"] != "901" || ssh["Seqnum"] != float64(1) ||
		ssh["EventTime"] != "2026-01-01T00:00:00.000000Z" {
		t.Fatalf("journal fields lost: %v", ssh)
	}
	// _COMM fallback when SYSLOG_IDENTIFIER is absent
	pam := recs[1]
	if pam["RecordType"] != "pam_session" || pam["SessionOp"] != "opened" || pam["ByUser"] != "alice" {
		t.Fatalf("journal pam via _COMM: %v", pam)
	}
}

// TestOverCapValueTruncates pins the PR #69 review fix: a DATA value over
// maxDataPayload — as stored, or once decompressed (the silent-xz case) —
// drops that field and marks the entry Truncated, never a silent prefix.
func TestOverCapValueTruncates(t *testing.T) {
	b := newJB(false)
	good := b.addData([]byte("MESSAGE=still here"), 0)
	rawBig := b.addData(append([]byte("RAWBIG="), bytes.Repeat([]byte{'a'}, maxDataPayload)...), 0)
	xzBig := b.addData(xzPayload(t, "XZBIG="+strings.Repeat("b", maxDataPayload)), objFlagXZ)
	e1 := b.addEntry(1, 1767225600000000, 5, []uint64{good, rawBig, xzBig})
	ea := b.addEntryArray(0, []uint64{e1})
	recs := decode(t, b.finish(ea, 1, fCompressedXZ))
	if len(recs) != 1 {
		t.Fatalf("entries: %d", len(recs))
	}
	r := recs[0]
	if r["Message"] != "still here" || r["Truncated"] != true {
		t.Fatalf("over-cap fields did not truncate the entry: %v", r)
	}
	if f, ok := r["Fields"].(map[string]any); ok {
		for _, k := range []string{"RAWBIG", "XZBIG"} {
			if _, kept := f[k]; kept {
				t.Fatalf("over-cap value %s kept: %v", k, f)
			}
		}
	}
}

// TestBinaryFieldHexed pins that a non-UTF-8 value reaches safeValue with
// its original bytes (Go string conversion is byte-preserving; the record
// splits on raw bytes) and lands hex-prefixed, not mangled.
func TestBinaryFieldHexed(t *testing.T) {
	b := newJB(false)
	d1 := b.addData([]byte("MESSAGE=ok"), 0)
	d2 := b.addData(append([]byte("BLOB="), 0xff, 0xfe, 0x01), 0)
	e1 := b.addEntry(1, 1767225600000000, 5, []uint64{d1, d2})
	ea := b.addEntryArray(0, []uint64{e1})
	recs := decode(t, b.finish(ea, 1, 0))
	if len(recs) != 1 {
		t.Fatalf("entries: %d", len(recs))
	}
	f, _ := recs[0]["Fields"].(map[string]any)
	if f["BLOB"] != "hex:fffe01" {
		t.Fatalf("binary value not hexed byte-faithfully: %v", recs[0])
	}
	if recs[0]["Truncated"] == true {
		t.Fatalf("binary value wrongly marked truncated: %v", recs[0])
	}
}
