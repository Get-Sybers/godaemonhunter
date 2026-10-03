package main

// imageitem_test proves the hunt runs ON a disk image: a stub gomount
// (GOMOUNT_BIN) stands in for the decoder and stages a minimal linux-core
// surface where a materialised root volume would put it; the layered run
// then treats it as the host, builds the knowledge store under
// <KNOWLEDGE_DIR>/<image>/, writes records under <OUT_DIR>/<subtool>/<image>/,
// and leaves no scratch behind.

import (
	"bytes"
	"encoding/json"
	"github.com/Get-Sybers/gopinfo/diskimage"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func gomountStub(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	stub := filepath.Join(dir, "gomount")
	script := `#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  case "$1" in --out) out="$2"; shift ;; esac
  shift
done
[ -n "$out" ] || exit 2
mkdir -p "$out/etc" "$out/var/log"
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
	// layer-2 output is per image too; gosyslog saw auth.log
	matches, _ := filepath.Glob(filepath.Join(out, "gosyslog", "srv.vmdk", "*", "gosyslog.jsonl"))
	if len(matches) == 0 {
		t.Fatalf("no gosyslog records under the image host; summary: %s", buf.String())
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
	matches, _ := filepath.Glob(filepath.Join(out, "srv.E01", "*", "gosyslog.jsonl"))
	if len(matches) == 0 {
		t.Fatalf("no records under <out>/<image>/: %s", buf.String())
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
