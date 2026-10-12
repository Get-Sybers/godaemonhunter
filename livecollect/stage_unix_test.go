//go:build unix

package livecollect

// stage_unix_test drives the collector against built fixture roots: the right
// files land at the right staged paths, a localtime symlink is captured as its
// target, non-regular and dangling entries are skipped (never fatal), a file
// reached twice (usrmerge) is staged once, the size cap holds, and the manifest
// carries live provenance. These exercise real filesystem behaviour, so they
// are unix-only — as live mode itself is.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func mk(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func staged(t *testing.T, dir, rel string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel)))
	return err == nil
}

func TestStageLinux(t *testing.T) {
	root := t.TempDir()
	mk(t, filepath.Join(root, "etc/os-release"), "ID=debian\n")
	mk(t, filepath.Join(root, "etc/hostname"), "web01\n")
	mk(t, filepath.Join(root, "etc/ssh/sshd_config"), "PermitRootLogin no\n")
	mk(t, filepath.Join(root, "var/log/auth.log"), "boot\n")
	mk(t, filepath.Join(root, "home/alice/.bash_history"), "id\n")
	mk(t, filepath.Join(root, "home/alice/.ssh/known_hosts"), "host ssh-ed25519 AAAA\n")

	// a localtime symlink into the zoneinfo db: the zone name is the target.
	mk(t, filepath.Join(root, "usr/share/zoneinfo/Europe/Berlin"), "TZif-binary")
	if err := os.Symlink("../usr/share/zoneinfo/Europe/Berlin", filepath.Join(root, "etc/localtime")); err != nil {
		t.Fatal(err)
	}
	// a dangling symlink and a fifo under a collected tree: both skipped.
	if err := os.Symlink("/nonexistent/target", filepath.Join(root, "etc/dangle")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "etc/afifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	// usrmerge: /lib -> /usr/lib, so lib/systemd/x.service is the same file as
	// usr/lib/systemd/x.service and must be staged exactly once.
	mk(t, filepath.Join(root, "usr/lib/systemd/x.service"), "[Unit]\n")
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}

	res, err := Stage(Options{OS: "linux", Root: root, WorkDir: t.TempDir(), Item: "host"})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}

	for _, rel := range []string{
		"etc/os-release", "etc/hostname", "etc/ssh/sshd_config", "etc/localtime",
		"var/log/auth.log", "home/alice/.bash_history", "home/alice/.ssh/known_hosts",
		"usr/lib/systemd/x.service",
	} {
		if !staged(t, res.Dir, rel) {
			t.Errorf("%s was not staged", rel)
		}
	}
	for _, rel := range []string{"etc/dangle", "etc/afifo", "lib/systemd/x.service"} {
		if staged(t, res.Dir, rel) {
			t.Errorf("%s should not have been staged", rel)
		}
	}

	// localtime is the captured target string, not the TZif content.
	lt, err := os.ReadFile(filepath.Join(res.Dir, "etc/localtime"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(lt); !strings.Contains(got, "zoneinfo/Europe/Berlin") {
		t.Errorf("localtime staged as %q, want the symlink target", got)
	}

	// the manifest carries a live meta row and a live-path row per file.
	meta, rows := readManifest(t, res.Dir)
	if meta.Volume != "live" {
		t.Errorf("manifest meta volume = %q, want live", meta.Volume)
	}
	osrel, ok := rows["etc/os-release"]
	if !ok {
		t.Fatal("no manifest row for etc/os-release")
	}
	if osrel.Path != "/etc/os-release" || osrel.Inode == 0 {
		t.Errorf("etc/os-release row = %+v, want on-host path and a non-zero inode", osrel)
	}
}

func TestStageMaxFile(t *testing.T) {
	root := t.TempDir()
	mk(t, filepath.Join(root, "etc/os-release"), "ID=debian\n") // 10 bytes
	mk(t, filepath.Join(root, "etc/hostname"), "x\n")           // 2 bytes

	res, err := Stage(Options{OS: "linux", Root: root, WorkDir: t.TempDir(), MaxFile: 3})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if staged(t, res.Dir, "etc/os-release") {
		t.Error("over-cap file was staged")
	}
	if !staged(t, res.Dir, "etc/hostname") {
		t.Error("under-cap file was skipped")
	}
	if res.Skipped == 0 {
		t.Error("over-cap skip was not counted")
	}
}

func TestStageDarwin(t *testing.T) {
	root := t.TempDir()
	mk(t, filepath.Join(root, "System/Library/CoreServices/SystemVersion.plist"), "<plist/>\n")
	mk(t, filepath.Join(root, "private/var/log/system.log"), "boot\n")
	mk(t, filepath.Join(root, "private/var/db/dslocal/nodes/Default/users/alice.plist"), "<plist/>\n")
	mk(t, filepath.Join(root, "Library/LaunchDaemons/com.evil.plist"), "<plist/>\n")
	mk(t, filepath.Join(root, "Users/bob/.zsh_history"), "whoami\n")

	res, err := Stage(Options{OS: "darwin", Root: root, WorkDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	for _, rel := range []string{
		"System/Library/CoreServices/SystemVersion.plist",
		"private/var/log/system.log",
		"private/var/db/dslocal/nodes/Default/users/alice.plist",
		"Library/LaunchDaemons/com.evil.plist",
		"Users/bob/.zsh_history",
	} {
		if !staged(t, res.Dir, rel) {
			t.Errorf("%s was not staged", rel)
		}
	}
}

// readManifest parses the stage's materialise.jsonl into its meta row and a
// staged-path -> row map.
func readManifest(t *testing.T, dir string) (mrow, map[string]mrow) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var meta mrow
	rows := map[string]mrow{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var r mrow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("manifest line %q: %v", line, err)
		}
		if r.Staged == "" {
			meta = r
			continue
		}
		rows[r.Staged] = r
	}
	return meta, rows
}
