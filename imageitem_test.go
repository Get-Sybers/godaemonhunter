package main

// imageitem_test proves the hunt runs ON a disk image: a stub gomount
// (GOMOUNT_BIN) stands in for the decoder and stages a minimal linux-core
// surface where a materialised root volume would put it; the layered run
// then treats it as the host, builds the knowledge store under
// <KNOWLEDGE_DIR>/<image>/, writes Layer-2 records flat at <OUT_DIR>/<subtool>/<asset-id>.jsonl,
// and leaves no scratch behind.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Get-Sybers/gopinfo/diskimage"
)

func gomountStub(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	stub := filepath.Join(dir, "gomount")
	// identify, answering as gomount 0.3.0 does: a uac-*.tar.gz|.tar|.zip
	// is a UAC collection (the [root] volume); any other archive is a zip
	// or tar of something else — exit 0, no volumes; a broken-* archive
	// cannot be read (exit 1 with the reason on stderr); probe-tmpdir.tar
	// reports the TMPDIR it was handed as its volume source; a disk image
	// is a plain Linux root. materialise: stage a minimal linux-core
	// surface and record TMPDIR, the spool dir the hunt hands gomount.
	// Every call is appended to $GOMOUNT_STUB_LOG when set.
	script := `#!/bin/sh
[ -n "${GOMOUNT_STUB_LOG:-}" ] && echo "$1 $2" >> "$GOMOUNT_STUB_LOG"
if [ "$1" = identify ]; then
  case "$2" in
    */uac-*.tar.gz|*/uac-*.tgz|*/uac-*.tar|*/uac-*.zip)
      echo '{"image":{"format":"gzip","size":1},"collection":{"tool":"uac","version":"3.4.0","hostname":"web01"},"volumes":[{"volume":1,"source":"[root]","fstype":"uac","os":"linux"},{"volume":2,"source":"uac","fstype":"uac-meta"}]}' ;;
    */probe-tmpdir.tar)
      echo "{\"image\":{\"format\":\"tar\",\"size\":1},\"volumes\":[{\"volume\":1,\"source\":\"${TMPDIR:-unset}\",\"fstype\":\"probe\"}]}" ;;
    */broken-*)
      echo "gomount: uac: spool: open /nowhere/gomount-uac-1.tar: no such file or directory" >&2; exit 1 ;;
    *.zip|*.tar|*.tar.gz|*.tgz)
      echo '{"image":{"format":"zip","size":1},"partitions":null,"volumes":null,"snapshots":[]}' ;;
    *)
      echo '{"image":{"format":"raw","size":1},"volumes":[{"volume":1,"source":"p1","fstype":"ext4","os":"linux (debian)"}]}' ;;
  esac
  exit 0
fi
out=""
while [ $# -gt 0 ]; do
  case "$1" in --out) out="$2"; shift ;; esac
  shift
done
[ -n "$out" ] || exit 2
mkdir -p "$out/etc" "$out/var/log"
printf '%s\n' "${TMPDIR:-unset}" > "$out/.spool-dir"
printf 'web01\n' > "$out/etc/hostname"
printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\n' > "$out/etc/os-release"
printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n' > "$out/etc/passwd"
printf 'root:x:0:\nalice:x:1000:\n' > "$out/etc/group"
printf 'Jan  1 00:00:01 web01 sshd[100]: Accepted password for alice from 10.0.0.5 port 4000 ssh2\n' > "$out/var/log/auth.log"
echo '{"tool":"gomount","subtool":"materialise","status":"ok","exit":0}'
`
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return stub
}

func TestHuntRunsOnImage(t *testing.T) {
	stub := gomountStub(t)
	in, out, work := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "srv.vmdk"), []byte("KDMV"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GOMOUNT_BIN":              stub,
		"GODAEMONHUNTER_INPUT_DIR": in, "GODAEMONHUNTER_OUT_DIR": out,
		"GODAEMONHUNTER_WORK_DIR": work, "GODAEMONHUNTER_IMAGE": "srv.vmdk",
	}), &buf)
	var sum huntSummary
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &sum); err != nil {
		t.Fatalf("summary: %v: %s", err, buf.String())
	}
	if code == 2 {
		t.Fatalf("exit %d: %s", code, buf.String())
	}
	if len(sum.Images) != 1 || sum.Images[0] != "srv.vmdk" {
		t.Fatalf("images = %v", sum.Images)
	}
	// the knowledge store is per image, under the store root
	if st, err := os.Stat(filepath.Join(out, "knowledge", "srv.vmdk")); err != nil || !st.IsDir() {
		t.Fatalf("knowledge/<image>/ missing: %v", err)
	}
	// layer-2 output is flat per asset; gosyslog saw auth.log
	if _, err := os.Stat(filepath.Join(out, "gosyslog", "srv.vmdk.jsonl")); err != nil {
		t.Fatalf("no gosyslog flat record for the image; summary: %s", buf.String())
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatalf("scratch left behind: %v", entries)
	}
	for _, ss := range sum.Subtools {
		if ss.Subtool != "srv.vmdk" {
			t.Fatalf("sub-run not attributed to the image: %+v", ss)
		}
	}
}

func TestSubtoolRunsOnImage(t *testing.T) {
	stub := gomountStub(t)
	in, out, work := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "srv.E01"), []byte("EVF"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	code := run([]string{"gosyslog"}, env(map[string]string{
		"GOMOUNT_BIN":        stub,
		"GOSYSLOG_INPUT_DIR": in, "GOSYSLOG_OUT_DIR": out, "GOSYSLOG_WORK_DIR": work, "GOSYSLOG_IMAGE": "srv.E01",
	}), &buf)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, buf.String())
	}
	if _, err := os.Stat(filepath.Join(out, "srv.E01.jsonl")); err != nil {
		t.Fatalf("no flat record at <out>/<asset-id>.jsonl: %s", buf.String())
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatalf("scratch left behind: %v", entries)
	}
}

func TestImageSelectionRejectsParts(t *testing.T) {
	stub := gomountStub(t)
	in := t.TempDir()
	for _, name := range []string{"disk-flat.vmdk", "disk-s002.vmdk", "host.E02", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(in, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := diskimage.SelectedImages(in, name); err == nil {
			t.Errorf("diskimage.SelectedImages(%q) accepted a part of another image / a non-image", name)
		}
	}
	// the Apple disk images gomount reads are items too
	for _, name := range []string{"installer.dmg", "backup.sparseimage", "host.E01", "disk.vmdk"} {
		if err := os.WriteFile(filepath.Join(in, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if imgs, err := diskimage.SelectedImages(in, name); err != nil || len(imgs) != 1 {
			t.Errorf("diskimage.SelectedImages(%q) = %v, %v; want the one image", name, imgs, err)
		}
		if !diskimage.IsImageItem(name) {
			t.Errorf("diskimage.IsImageItem(%q) = false", name)
		}
	}
	_ = stub
}

// TestHuntDiscoversCollections: without IMAGE, every archive directly under
// the input tree that gomount identify confirms as a UAC collection is a
// host beside the disk images; a zip of anything else is skipped, and the
// acquisition-log sidecar is never an item.
func TestHuntDiscoversCollections(t *testing.T) {
	stub := gomountStub(t)
	in, out, work := t.TempDir(), t.TempDir(), t.TempDir()
	for _, name := range []string{"uac-web01-linux-20261014113903.tar.gz", "uac-web01-linux-20261014113903.log", "other.zip", "broken-case.tar.gz", "srv.vmdk"} {
		if err := os.WriteFile(filepath.Join(in, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GOMOUNT_BIN":              stub,
		"GODAEMONHUNTER_INPUT_DIR": in, "GODAEMONHUNTER_OUT_DIR": out, "GODAEMONHUNTER_WORK_DIR": work,
	}), &buf)
	var sum huntSummary
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &sum); err != nil {
		t.Fatalf("summary: %v: %s", err, buf.String())
	}
	if code == 2 {
		t.Fatalf("exit %d: %s", code, buf.String())
	}
	if strings.Join(sum.Images, " ") != "srv.vmdk uac-web01-linux-20261014113903.tar.gz" {
		t.Fatalf("images = %v", sum.Images)
	}
	if strings.Join(sum.Collections, " ") != "uac-web01-linux-20261014113903.tar.gz" {
		t.Fatalf("collections = %v", sum.Collections)
	}
	for _, host := range sum.Images {
		if st, err := os.Stat(filepath.Join(out, "knowledge", host)); err != nil || !st.IsDir() {
			t.Errorf("knowledge/%s/ missing: %v", host, err)
		}
		if _, err := os.Stat(filepath.Join(out, "gosyslog", host+".jsonl")); err != nil {
			t.Errorf("no gosyslog flat record for %s", host)
		}
	}
	for _, name := range []string{"other.zip", "broken-case.tar.gz"} {
		if _, err := os.Stat(filepath.Join(out, "knowledge", name)); err == nil {
			t.Errorf("%s was hunted as a collection", name)
		}
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatalf("scratch left behind: %v", entries)
	}
}

// TestCollectionNamedAndSpooledOnWork: IMAGE may name a collection outright
// (no identify round-trip), and gomount's spool of a gzip'd archive lands
// on the disk-backed work dir, never the container's tmpfs.
func TestCollectionNamedAndSpooledOnWork(t *testing.T) {
	stub := gomountStub(t)
	in, out, work := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "case.zip"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	code := run([]string{"gosyslog"}, env(map[string]string{
		"GOMOUNT_BIN":        stub,
		"GOSYSLOG_INPUT_DIR": in, "GOSYSLOG_OUT_DIR": out, "GOSYSLOG_WORK_DIR": work, "GOSYSLOG_IMAGE": "case.zip",
	}), &buf)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, buf.String())
	}
	if _, err := os.Stat(filepath.Join(out, "case.zip.jsonl")); err != nil {
		t.Fatalf("no flat record at <out>/<asset-id>.jsonl: %s", buf.String())
	}
	// the stub recorded the TMPDIR it was handed in the scratch (removed
	// afterwards), so prove it through a hunt that keeps the stage: the
	// spool dir is the work dir
	var hunt bytes.Buffer
	code = run(nil, env(map[string]string{
		"GOMOUNT_BIN":              stub,
		"GODAEMONHUNTER_INPUT_DIR": in, "GODAEMONHUNTER_OUT_DIR": t.TempDir(), "GODAEMONHUNTER_WORK_DIR": work,
		"GODAEMONHUNTER_IMAGE": "case.zip", "GODAEMONHUNTER_LOG_LEVEL": "debug",
	}), &hunt)
	if code == 2 {
		t.Fatalf("hunt exit %d: %s", code, hunt.String())
	}
	var sum huntSummary
	if err := json.Unmarshal(bytes.TrimSpace(hunt.Bytes()), &sum); err != nil {
		t.Fatal(err)
	}
	if len(sum.Collections) != 1 || sum.Collections[0] != "case.zip" {
		t.Errorf("collections = %v", sum.Collections)
	}
}

func TestSpoolDirIsTheWorkDir(t *testing.T) {
	stub := gomountStub(t)
	in, work := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "uac-x.tar.gz"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	scratch, err := materialiseImage(env(map[string]string{"GOMOUNT_BIN": stub}), work, filepath.Join(in, "uac-x.tar.gz"), imageSets)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(scratch)
	b, err := os.ReadFile(filepath.Join(scratch, ".spool-dir"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != work {
		t.Errorf("gomount ran with TMPDIR=%q, want the work dir %q", got, work)
	}
}

// TestArchiveCandidatesAndSelection: an archive is a candidate by name
// (never the acquisition-log sidecar), selectable outright by IMAGE, and
// invisible to the disk-image discovery.
func TestArchiveCandidatesAndSelection(t *testing.T) {
	in := t.TempDir()
	for _, name := range []string{"uac-b.zip", "uac-a.tar.gz", "uac-a.log", "disk.vmdk", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(in, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(in, "folder.zip"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := discoverArchives(in)
	if len(got) != 2 || filepath.Base(got[0]) != "uac-a.tar.gz" || filepath.Base(got[1]) != "uac-b.zip" {
		t.Errorf("discoverArchives = %v", got)
	}
	for _, name := range []string{"uac-a.tar.gz", "uac-b.zip", "disk.vmdk"} {
		if items, err := selectedItems(in, name); err != nil || len(items) != 1 {
			t.Errorf("selectedItems(%q) = %v, %v", name, items, err)
		}
	}
	for _, name := range []string{"uac-a.log", "folder.zip", "missing.tar.gz"} {
		if _, err := selectedItems(in, name); err == nil {
			t.Errorf("selectedItems(%q) accepted a non-item", name)
		}
	}
	if imgs := diskimage.DiscoverImages(in); len(imgs) != 1 || filepath.Base(imgs[0]) != "disk.vmdk" {
		t.Errorf("DiscoverImages = %v (archives are not images)", imgs)
	}
}

func TestImageSelectionErrors(t *testing.T) {
	stub := gomountStub(t)
	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GOMOUNT_BIN":              stub,
		"GODAEMONHUNTER_INPUT_DIR": t.TempDir(), "GODAEMONHUNTER_OUT_DIR": t.TempDir(),
		"GODAEMONHUNTER_WORK_DIR": t.TempDir(), "GODAEMONHUNTER_IMAGE": "missing.vmdk",
	}), &buf)
	if code != 2 || !strings.Contains(buf.String(), "config_error") {
		t.Fatalf("missing image: exit %d: %s", code, buf.String())
	}
}

// TestIdentifyRunsOnTheWorkDir: every gomount run gets TMPDIR = the work
// dir — identify included, since it spools a gzip'd collection exactly as
// materialise does and the container's /tmp is a small tmpfs or, in a
// FROM scratch image, absent. The stub reports the TMPDIR it saw as the
// volume source.
func TestIdentifyRunsOnTheWorkDir(t *testing.T) {
	stub := gomountStub(t)
	in, work := t.TempDir(), filepath.Join(t.TempDir(), "work")
	probe := filepath.Join(in, "probe-tmpdir.tar")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	vols, err := identifyVolumes(env(map[string]string{"GOMOUNT_BIN": stub}), work, probe)
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 1 || vols[0].Source != work {
		t.Fatalf("identify ran with TMPDIR %q, want the work dir %q", vols[0].Source, work)
	}
	// a candidate gomount cannot read: its first stderr line rides the error
	broken := filepath.Join(in, "broken-case.tar.gz")
	if err := os.WriteFile(broken, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := identifyVolumes(env(map[string]string{"GOMOUNT_BIN": stub}), work, broken); err == nil || !strings.Contains(err.Error(), "uac: spool") {
		t.Fatalf("broken archive: err = %v, want gomount's reason", err)
	}
	// discovery makes the work dir first, so the spool has somewhere to
	// land; the probe (no uac volume) and the broken archive are skipped
	if err := os.WriteFile(filepath.Join(in, "uac-web01-linux-20261014113903.tar.gz"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := discoverCollections(env(map[string]string{"GOMOUNT_BIN": stub}), in, work); len(got) != 1 || filepath.Base(got[0]) != "uac-web01-linux-20261014113903.tar.gz" {
		t.Fatalf("discoverCollections = %v", got)
	}
	if st, err := os.Stat(work); err != nil || !st.IsDir() {
		t.Errorf("work dir not made before identify: %v", err)
	}
}

// TestNamedCollectionIsNeverReIdentified: a collection named by IMAGE is
// one host's root tree, never a Mac Data/System pair, so after materialise
// no second identify spools the archive again.
func TestNamedCollectionIsNeverReIdentified(t *testing.T) {
	stub := gomountStub(t)
	in, out, work := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "uac-web01-linux-20261014113903.tar.gz"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "calls.log")
	t.Setenv("GOMOUNT_STUB_LOG", log)
	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GOMOUNT_BIN":              stub,
		"GODAEMONHUNTER_INPUT_DIR": in, "GODAEMONHUNTER_OUT_DIR": out, "GODAEMONHUNTER_WORK_DIR": work,
		"GODAEMONHUNTER_IMAGE": "uac-web01-linux-20261014113903.tar.gz",
	}), &buf)
	if code == 2 {
		t.Fatalf("exit %d: %s", code, buf.String())
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "identify") {
		t.Errorf("a named collection was identified:\n%s", calls)
	}
	if !strings.Contains(string(calls), "materialise") {
		t.Errorf("no materialise call:\n%s", calls)
	}
	// a disk image still gets the Mac second-pass identify
	if err := os.WriteFile(filepath.Join(in, "srv.vmdk"), []byte("KDMV"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(log)
	buf.Reset()
	run(nil, env(map[string]string{
		"GOMOUNT_BIN":              stub,
		"GODAEMONHUNTER_INPUT_DIR": in, "GODAEMONHUNTER_OUT_DIR": t.TempDir(), "GODAEMONHUNTER_WORK_DIR": work,
		"GODAEMONHUNTER_IMAGE": "srv.vmdk",
	}), &buf)
	calls, _ = os.ReadFile(log)
	if !strings.Contains(string(calls), "identify") {
		t.Errorf("a disk image skipped the Mac second-pass identify:\n%s", calls)
	}
}
