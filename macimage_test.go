package main

// macimage_test.go proves the Mac image run: the first pass stages the
// Data volume's surface, gomount identify shows a System volume beside it,
// the second pass pulls the System volume's version plist and Apple's
// launchd jobs into the same tree, and the run comes out enriched with the
// OS name — every file's Origin naming its own volume.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func macGomountStub(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	stub := filepath.Join(dir, "gomount")
	script := `#!/bin/sh
if [ "$1" = "identify" ]; then
  echo '{"volumes":[{"volume":1,"source":"p1","fstype":"vfat"},{"volume":3,"source":"p2/apfs1","fstype":"apfs","os":"macos (data)"},{"volume":7,"source":"p2/apfs5","fstype":"apfs","os":"macos (system)"}]}'
  exit 0
fi
out=""; vol=""
while [ $# -gt 0 ]; do
  case "$1" in --out) out="$2"; shift ;; --volume) vol="$2"; shift ;; esac
  shift
done
[ -n "$out" ] || exit 2
if [ "$vol" = "7" ]; then
  mkdir -p "$out/System/Library/CoreServices" "$out/System/Library/LaunchDaemons"
  printf '<plist version="1.0"><dict><key>ProductName</key><string>macOS</string><key>ProductVersion</key><string>12.7.3</string><key>ProductBuildVersion</key><string>21H1015</string></dict></plist>' > "$out/System/Library/CoreServices/SystemVersion.plist"
  printf '<plist version="1.0"><dict><key>Label</key><string>com.apple.example</string><key>Program</key><string>/usr/libexec/example</string></dict></plist>' > "$out/System/Library/LaunchDaemons/com.apple.example.plist"
  printf '{"image":"mac.E01","volume":"p2/apfs5","path":"/System/Library/CoreServices/SystemVersion.plist","inode":11}\n{"image":"mac.E01","volume":"p2/apfs5","path":"/System/Library/LaunchDaemons/com.apple.example.plist","inode":12}\n' > "$out/materialise.jsonl"
else
  mkdir -p "$out/private/var/db/dslocal/nodes/Default/users" "$out/Library/Preferences/SystemConfiguration"
  printf '<plist version="1.0"><dict><key>name</key><array><string>gl</string></array><key>uid</key><array><string>501</string></array><key>gid</key><array><string>20</string></array></dict></plist>' > "$out/private/var/db/dslocal/nodes/Default/users/gl.plist"
  printf '<plist version="1.0"><dict><key>System</key><dict><key>System</key><dict><key>HostName</key><string>mba.local</string></dict></dict></dict></plist>' > "$out/Library/Preferences/SystemConfiguration/preferences.plist"
  printf '{"image":"mac.E01","volume":"p2/apfs1","path":"/Library/Preferences/SystemConfiguration/preferences.plist","inode":21}\n{"image":"mac.E01","volume":"p2/apfs1","path":"/private/var/db/dslocal/nodes/Default/users/gl.plist","inode":22}\n' > "$out/materialise.jsonl"
fi
echo '{"tool":"gomount","subtool":"materialise","status":"ok","exit":0}'
`
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return stub
}

func TestHuntPullsMacSystemVolume(t *testing.T) {
	stub := macGomountStub(t)
	in, out, work := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "mac.E01"), []byte("EVF"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	code := run(nil, env(map[string]string{
		"GOMOUNT_BIN":              stub,
		"GODAEMONHUNTER_INPUT_DIR": in, "GODAEMONHUNTER_OUT_DIR": out,
		"GODAEMONHUNTER_WORK_DIR": work, "GODAEMONHUNTER_IMAGE": "mac.E01",
	}), &buf)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, buf.String())
	}
	// records land per item under <OUT_DIR>/<tool or knowledge>/<image>/<item>/
	read := func(glob string) []map[string]any {
		files, _ := filepath.Glob(filepath.Join(out, glob))
		if len(files) == 0 {
			t.Fatalf("%s: no record files", glob)
		}
		var rows []map[string]any
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
				var m map[string]any
				if err := json.Unmarshal(line, &m); err != nil {
					t.Fatal(err)
				}
				rows = append(rows, m)
			}
		}
		return rows
	}
	// the OS came off the System volume, and says so
	var osRow map[string]any
	for _, r := range read("knowledge/mac.E01/*/gomachost.jsonl") {
		if r["RecordType"] == "os_release" {
			osRow = r
		}
	}
	if osRow == nil || osRow["PrettyName"] != "macOS 12.7.3 (21H1015)" {
		t.Fatalf("os_release: %v", osRow)
	}
	if origin, _ := osRow["Origin"].(map[string]any); origin["Volume"] != "p2/apfs5" || origin["Image"] != "mac.E01" {
		t.Fatalf("os_release origin: %v", osRow["Origin"])
	}
	// Apple's daemon in the system domain, the Data-side files' provenance intact
	jobs := read("golaunchd/mac.E01/*/golaunchd.jsonl")
	if len(jobs) != 1 || jobs[0]["Label"] != "com.apple.example" || jobs[0]["Domain"] != "system" || jobs[0]["Kind"] != "daemon" {
		t.Fatalf("launchd: %v", jobs)
	}
	users := read("knowledge/mac.E01/*/gomacusers.jsonl")
	if origin, _ := users[0]["Origin"].(map[string]any); origin["Volume"] != "p2/apfs1" {
		t.Fatalf("account origin: %v", users[0]["Origin"])
	}
	// every Layer-2 record is enriched with the host's identity from both volumes
	host, _ := jobs[0]["Host"].(map[string]any)
	if host["Hostname"] != "mba.local" || host["OS"] != "macOS 12.7.3 (21H1015)" {
		t.Fatalf("host block: %v", jobs[0]["Host"])
	}
	// the scratch and its side tree are gone
	entries, _ := os.ReadDir(work)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "mac.E01") {
			t.Fatalf("scratch left behind: %s", e.Name())
		}
	}
}
