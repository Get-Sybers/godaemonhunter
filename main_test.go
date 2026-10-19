package main

// main_test.go proves the one-binary shape: subtool dispatch runs a
// parser's ordinary batch mode, hunt runs the layered pipeline — Layer 1
// builds the knowledge store, Layer 2 comes out enriched by it — and the
// whole run prints exactly one aggregate JSON line.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Get-Sybers/gopinfo/batch"
)

func writeFixtures(t *testing.T, in string) {
	t.Helper()
	mk := func(rel, content string) {
		p := filepath.Join(in, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	mk("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n")
	mk("etc/hostname", "web01\n")
	mk("etc/timezone", "Europe/Berlin\n")
	mk("var/log/audit/audit.log",
		`type=SYSCALL msg=audit(1767225600.123:42): arch=c000003e syscall=59 success=yes exit=0 ppid=1200 pid=1201 auid=1000 uid=1000 gid=1000 euid=1000 ses=3 tty=pts0 comm="ls" exe="/usr/bin/ls" key="exec_log"`+"\n"+
			`type=EOE msg=audit(1767225600.123:42):`+"\n")
	mk("var/log/syslog", "Jan 10 22:14:02 web01 systemd[1]: Started daily apt activities.\n")
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestSubtoolDispatch(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	p := filepath.Join(in, "home/alice/.local/share/Trash/info/x.txt.trashinfo")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte("[Trash Info]\nPath=/home/alice/x.txt\nDeletionDate=2026-03-01T22:14:02\n"), 0o644)

	var buf bytes.Buffer
	code := run([]string{"gotrash"}, env(map[string]string{
		"GOTRASH_INPUT_DIR": in, "GOTRASH_OUT_DIR": out, "GOTRASH_WORK_DIR": t.TempDir(),
	}), &buf)
	if code != 0 {
		t.Fatalf("dispatch exit %d: %s", code, buf.String())
	}
	var sum map[string]any
	json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &sum)
	if sum["tool"] != "gotrash" || sum["records"] != float64(1) {
		t.Fatalf("summary: %v", sum)
	}
}

// TestEverySubtoolEmptyTree is the batch contract over the whole registry
// (the per-parser binaries are gone; this is their binary-level test now):
// an empty evidence tree is exit 1, status "nothing", the tool's own name.
func TestEverySubtoolEmptyTree(t *testing.T) {
	for _, s := range subs {
		pfx := batch.Prefix(s.name)
		var buf bytes.Buffer
		code := run([]string{s.name}, env(map[string]string{
			pfx + "_INPUT_DIR": t.TempDir(), pfx + "_OUT_DIR": t.TempDir(), pfx + "_WORK_DIR": t.TempDir(),
		}), &buf)
		if code != 1 {
			t.Fatalf("%s: empty-tree exit %d: %s", s.name, code, buf.String())
		}
		var sum map[string]any
		json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &sum)
		if sum["tool"] != s.name || sum["status"] != "nothing" {
			t.Fatalf("%s: summary %v", s.name, sum)
		}
	}
}

func TestUnknownAndUsage(t *testing.T) {
	var buf bytes.Buffer
	if code := run([]string{"gonosuch"}, env(nil), &buf); code != 2 {
		t.Fatalf("unknown subtool exit %d", code)
	}
	// registry is a byakugan model, but nothing here feeds it — not accepted.
	if code := run([]string{"registry"}, env(nil), &buf); code != 2 {
		t.Fatalf("unfed model word exit %d", code)
	}
	if code := run([]string{"file", "registry"}, env(nil), &buf); code != 2 {
		t.Fatalf("mixed valid+invalid streams exit %d", code)
	}
	buf.Reset()
	if code := run([]string{"--version"}, env(nil), &buf); code != 0 || !strings.HasPrefix(buf.String(), "godaemonhunter ") {
		t.Fatalf("version: %d %q", code, buf.String())
	}
}

// TestBareIsAllStreams: no arguments IS the default run — every stream,
// the layered hunt. (Here /input is absent, so it lands on config_error,
// but it lands there as a hunt: one summary line naming all streams.)
func TestBareIsAllStreams(t *testing.T) {
	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GODAEMONHUNTER_INPUT_DIR": filepath.Join(t.TempDir(), "missing"),
		"GODAEMONHUNTER_OUT_DIR":   t.TempDir(),
		"GODAEMONHUNTER_WORK_DIR":  t.TempDir(),
	}), &buf)
	if code != 2 {
		t.Fatalf("bare run with missing input: exit %d", code)
	}
	var sum huntSummary
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &sum); err != nil {
		t.Fatalf("bare run printed no summary: %v", err)
	}
	if sum.Tool != "godaemonhunter" || len(sum.Streams) != len(streams) {
		t.Fatalf("bare run is not the all-streams hunt: %+v", sum)
	}
}

// TestStreamRegistryConsistent: every stream maps only to registered
// Layer-2 parsers, and together the streams cover all of Layer 2 — so
// the default (all streams) is the whole matrix.
func TestStreamRegistryConsistent(t *testing.T) {
	l2 := map[string]bool{}
	for _, s := range subs {
		if s.layer == 2 {
			l2[s.name] = false
		}
	}
	for word, names := range streams {
		for _, n := range names {
			if _, ok := l2[n]; !ok {
				t.Fatalf("stream %q names %q, not a Layer-2 parser", word, n)
			}
			l2[n] = true
		}
	}
	for n, covered := range l2 {
		if !covered {
			t.Fatalf("Layer-2 parser %q feeds no stream", n)
		}
	}
}

// TestStreamScoped: one stream word runs Layer 1 plus exactly that
// stream's parsers, and the summary names the stream.
func TestStreamScoped(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	writeFixtures(t, in)

	var buf bytes.Buffer
	code := run([]string{"process"}, env(map[string]string{
		"GODAEMONHUNTER_INPUT_DIR": in, "GODAEMONHUNTER_OUT_DIR": out,
		"GODAEMONHUNTER_WORK_DIR": t.TempDir(),
	}), &buf)
	if code != 0 {
		t.Fatalf("stream run exit %d: %s", code, buf.String())
	}
	var sum huntSummary
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &sum); err != nil {
		t.Fatal(err)
	}
	if len(sum.Streams) != 1 || sum.Streams[0] != "process" {
		t.Fatalf("streams: %v", sum.Streams)
	}
	layer1 := 0
	for _, s := range subs {
		if s.layer == 1 {
			layer1++
		}
	}
	if want := layer1 + len(streams["process"]); len(sum.Subtools) != want {
		t.Fatalf("subtool count %d, want %d (Layer 1 + the stream): %+v", len(sum.Subtools), want, sum.Streams)
	}
	if _, err := os.Stat(filepath.Join(out, "goauditd")); err != nil {
		t.Fatal("process stream did not run goauditd")
	}
	for _, skipped := range []string{"gotrash", "goctl", "gounit"} {
		if _, err := os.Stat(filepath.Join(out, skipped)); err == nil {
			t.Fatalf("%s ran outside its stream", skipped)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "knowledge")); err != nil {
		t.Fatal("Layer 1 did not run")
	}
}

func TestHuntLayeredAndEnriched(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	writeFixtures(t, in)

	var buf bytes.Buffer
	code := run([]string{"hunt"}, env(map[string]string{
		"GODAEMONHUNTER_INPUT_DIR": in, "GODAEMONHUNTER_OUT_DIR": out,
		"GODAEMONHUNTER_WORK_DIR": t.TempDir(),
	}), &buf)
	if code != 0 {
		t.Fatalf("hunt exit %d: %s", code, buf.String())
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout is not one line: %d", len(lines))
	}
	var sum huntSummary
	if err := json.Unmarshal([]byte(lines[0]), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Status != "ok" || sum.Tool != "godaemonhunter" || len(sum.Subtools) != len(subs) {
		t.Fatalf("aggregate: %+v", sum)
	}
	if len(sum.Streams) != len(streams) {
		t.Fatalf("default hunt is not all streams: %v", sum.Streams)
	}

	// Layer 1 landed in the knowledge dir
	if _, err := os.Stat(filepath.Join(out, "knowledge")); err != nil {
		t.Fatal("knowledge dir missing")
	}

	// Layer 2 came out enriched: the audit event resolved uid 1000 and
	// carries the Host block; the syslog line got the host's zone
	// (Berlin winter, 22:14 local == 21:14Z).
	audit := readOne(t, filepath.Join(out, "goauditd"), "goauditd.jsonl")
	if audit["UIDName"] != "alice" || audit["UID"] != "1000" {
		t.Fatalf("audit enrichment: %v", audit)
	}
	host := audit["Host"].(map[string]any)
	if host["Hostname"] != "web01" || host["Timezone"] != "Europe/Berlin" {
		t.Fatalf("host block: %v", host)
	}
	syslog := readOne(t, filepath.Join(out, "gosyslog"), "gosyslog.jsonl")
	if syslog["EventTime"] != "2026-01-10T21:14:02.000000Z" {
		t.Fatalf("zone not applied: %v", syslog["EventTime"])
	}
}

// TestHuntStampsAssetIdentityOrigin proves the evidence-asset identity the
// gopinfo↔gomount Origin contract adds (gopinfo v0.3.0): a materialise.jsonl
// carrying the image-scoped image_sha256/disk_serial/disk_id and the
// volume-scoped volume_guid/part_guid/part_offset is joined onto every record
// as Origin, beside the existing Image/Volume/FSUUID/Label/Path/Inode, with the
// host's own machine id riding Host.MachineID. No parser knows the fields — the
// batch runtime stamps them at one shared site, so the whole matrix inherits
// them from the dependency bump alone.
func TestHuntStampsAssetIdentityOrigin(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	mk := func(rel, content string) {
		p := filepath.Join(in, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("etc/machine-id", "a1b2c3d4e5f60718293a4b5c6d7e8f90\n")
	mk("etc/hostname", "web01\n")
	mk("etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n")
	mk("var/log/auth.log", "Jan 10 02:14:07 web01 sshd[2211]: Accepted password for alice from 10.0.0.9 port 51002 ssh2\n")

	const (
		img      = "host01.E01"
		diskSer  = "TEST-EWF-SN-0001"
		diskID   = "ecf3c5a8-50b0-4d2d-8a6a-ed0c0ea429e9"
		imgSHA   = "40f5de615e7a99dc984b7ca2c94503849d92bd185c613f32c0615b35fab3e32a"
		vol      = "p2"
		fsuuid   = "21111111-2222-3333-4444-555555555555"
		label    = "rootfs"
		partGUID = "a0c564ae-2534-433a-97d8-a65d636e205c"
		partOff  = 1048576
	)
	// Written as gomount v0.4.0 writes it: the image-scoped keys on the
	// path-less metadata row, the volume-scoped keys on every per-file row.
	volRow := func(path string, inode int) string {
		return fmt.Sprintf(`{"image":%q,"volume":%q,"fsuuid":%q,"label":%q,"volume_guid":%q,"part_guid":%q,"part_offset":%d,"path":%q,"inode":%d}`,
			img, vol, fsuuid, label, fsuuid, partGUID, partOff, path, inode)
	}
	mk("materialise.jsonl", strings.Join([]string{
		fmt.Sprintf(`{"path":"","image":%q,"disk_serial":%q,"disk_id":%q,"image_sha256":%q}`, img, diskSer, diskID, imgSHA),
		volRow("/etc/machine-id", 11),
		volRow("/etc/hostname", 13),
		volRow("/etc/os-release", 12),
		volRow("/var/log/auth.log", 21),
	}, "\n")+"\n")

	var buf bytes.Buffer
	code := run([]string{"hunt"}, env(map[string]string{
		"GODAEMONHUNTER_INPUT_DIR": in, "GODAEMONHUNTER_OUT_DIR": out,
		"GODAEMONHUNTER_WORK_DIR": t.TempDir(),
	}), &buf)
	if code != 0 {
		t.Fatalf("hunt exit %d: %s", code, buf.String())
	}

	// a Layer-2 record (gosyslog, off auth.log) carries the joined Origin.
	row := readOne(t, filepath.Join(out, "gosyslog"), "gosyslog.jsonl")
	origin, ok := row["Origin"].(map[string]any)
	if !ok {
		t.Fatalf("no Origin on the gosyslog record: %v", row)
	}
	wantStr := map[string]string{
		// the pre-existing provenance, untouched by the bump
		"Image": img, "Volume": vol, "FSUUID": fsuuid, "Label": label,
		"Path": "/var/log/auth.log",
		// the evidence-asset identity the contract adds
		"ImageSHA256": imgSHA, "DiskSerial": diskSer, "DiskID": diskID,
		"VolumeGUID": fsuuid, "PartGUID": partGUID,
	}
	for k, want := range wantStr {
		if got, _ := origin[k].(string); got != want {
			t.Errorf("Origin.%s = %q, want %q", k, got, want)
		}
	}
	if origin["Inode"] != float64(21) {
		t.Errorf("Origin.Inode = %v, want 21", origin["Inode"])
	}
	if origin["PartOffset"] != float64(partOff) {
		t.Errorf("Origin.PartOffset = %v, want %d", origin["PartOffset"], partOff)
	}
	// host.id is the host's own machine id, enriched from the Layer-1 store.
	host, _ := row["Host"].(map[string]any)
	if host["MachineID"] != "a1b2c3d4e5f60718293a4b5c6d7e8f90" {
		t.Errorf("Host.MachineID = %v, want the staged machine id", host["MachineID"])
	}
}

func readOne(t *testing.T, root, name string) map[string]any {
	t.Helper()
	var rec map[string]any
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != name || rec != nil {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		first := strings.SplitN(strings.TrimSpace(string(b)), "\n", 2)[0]
		return json.Unmarshal([]byte(first), &rec)
	})
	if err != nil || rec == nil {
		t.Fatalf("no %s under %s: %v", name, root, err)
	}
	return rec
}

// TestContractLayersMatchRegistry: contract.yml's layer1/layer2 (what a
// per-parser driver reads) name exactly the binary's Layer-1 and Layer-2
// parsers, in registry order.
func TestContractLayersMatchRegistry(t *testing.T) {
	want := map[string][]string{}
	for _, s := range subs {
		key := "layer" + strconv.Itoa(s.layer)
		want[key] = append(want[key], s.name)
	}
	re := regexp.MustCompile(`(?m)^(layer[12]):\s*\[([^\]]*)\]`)
	got := map[string][]string{}
	for _, m := range re.FindAllStringSubmatch(contractYML, -1) {
		for _, n := range strings.Split(m[2], ",") {
			got[m[1]] = append(got[m[1]], strings.TrimSpace(n))
		}
	}
	for _, key := range []string{"layer1", "layer2"} {
		if strings.Join(got[key], " ") != strings.Join(want[key], " ") {
			t.Fatalf("contract %s = %v, registry has %v", key, got[key], want[key])
		}
	}
}
