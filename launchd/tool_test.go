package launchd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/get-sybers/gopinfo/record"
)

const agent = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>Label</key><string>org.keepassxc.KeePassXC</string>
	<key>ProgramArguments</key><array><string>/Applications/KeePassXC.app/Contents/MacOS/KeePassXC</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
	<key>StartCalendarInterval</key><array><dict><key>Hour</key><integer>3</integer><key>Minute</key><integer>0</integer></dict></array>
	<key>StartInterval</key><integer>3600</integer>
	<key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin</string></dict>
	<key>MachServices</key><dict><key>org.keepassxc.xpc</key><true/></dict>
	<key>StandardOutPath</key><string>/dev/null</string>
	<key>LimitLoadToSessionType</key><string>Aqua</string>
</dict></plist>`

func parseTo(t *testing.T, family, rel, content string) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseByFamily(strings.NewReader(content), family, rel, w); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	w.Flush()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestClassifyAndLocation(t *testing.T) {
	cases := map[string][3]string{
		"Library/LaunchDaemons/com.x.plist":                       {"job", "daemon", "library"},
		"Library/LaunchAgents/com.x.plist":                        {"job", "agent", "library"},
		"System/Library/LaunchDaemons/com.apple.x.plist":          {"job", "daemon", "system"},
		"Users/gl/Library/LaunchAgents/org.keepassxc.plist":       {"job", "agent", "user"},
		"private/var/root/Library/LaunchAgents/x.plist":           {"job", "agent", "user"},
		"private/var/db/com.apple.xpc.launchd/disabled.plist":     {"override", "", ""},
		"private/var/db/com.apple.xpc.launchd/disabled.501.plist": {"override", "", ""},
		"Library/Preferences/com.apple.x.plist":                   {"", "", ""},
		"Library/LaunchAgents/readme.txt":                         {"", "", ""},
	}
	for rel, want := range cases {
		if got := classify(rel); got != want[0] {
			t.Errorf("%s: family %q, want %q", rel, got, want[0])
		}
		if want[0] == "job" {
			kind, domain, _ := location(rel)
			if kind != want[1] || domain != want[2] {
				t.Errorf("%s: %s/%s, want %s/%s", rel, kind, domain, want[1], want[2])
			}
		}
	}
	if _, _, owner := location("Users/gl/Library/LaunchAgents/x.plist"); owner != "gl" {
		t.Fatalf("owner %q", owner)
	}
}

func TestJob(t *testing.T) {
	recs := parseTo(t, "job", "Users/gl/Library/LaunchAgents/org.keepassxc.KeePassXC.plist", agent)
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	r := recs[0]
	if r["RecordType"] != "launchd_job" || r["Label"] != "org.keepassxc.KeePassXC" || r["Kind"] != "agent" || r["Domain"] != "user" || r["Owner"] != "gl" {
		t.Fatalf("head: %v", r)
	}
	if r["RunAtLoad"] != true || r["KeepAlive"] != `{"SuccessfulExit":false}` || r["StartInterval"] != float64(3600) {
		t.Fatalf("run keys: %v", r)
	}
	if sci, _ := r["StartCalendarInterval"].([]any); len(sci) != 1 || sci[0] != "Minute=0 Hour=3" {
		t.Fatalf("calendar: %v", r["StartCalendarInterval"])
	}
	if args, _ := r["ProgramArguments"].([]any); len(args) != 1 || !strings.HasSuffix(args[0].(string), "KeePassXC") {
		t.Fatalf("args: %v", r["ProgramArguments"])
	}
	if env, _ := r["EnvironmentVariables"].(map[string]any); env["PATH"] != "/usr/bin" {
		t.Fatalf("env: %v", r["EnvironmentVariables"])
	}
	if ms, _ := r["MachServices"].([]any); len(ms) != 1 || ms[0] != "org.keepassxc.xpc" {
		t.Fatalf("mach: %v", r["MachServices"])
	}
	if sess, _ := r["LimitLoadToSessionType"].([]any); len(sess) != 1 || sess[0] != "Aqua" {
		t.Fatalf("session: %v", r["LimitLoadToSessionType"])
	}
	if keys, _ := r["Keys"].([]any); len(keys) != 10 {
		t.Fatalf("keys: %v", r["Keys"])
	}
	// an empty job file is recorded, labelled by its name, with no keys
	recs = parseTo(t, "job", "Users/gl/Library/LaunchAgents/com.google.keystone.agent.plist", `<plist version="1.0"><dict/></plist>`)
	if recs[0]["Label"] != "com.google.keystone.agent" || recs[0]["Keys"] != nil {
		t.Fatalf("empty job: %v", recs[0])
	}
	// a staged symlink: the target path stands in for the plist
	recs = parseTo(t, "job", "System/Library/LaunchAgents/com.apple.SafariLaunchAgent.plist", "../../../Library/Apple/System/Library/LaunchAgents/com.apple.SafariLaunchAgent.plist")
	if recs[0]["Label"] != "com.apple.SafariLaunchAgent" || recs[0]["LinkTarget"] != "../../../Library/Apple/System/Library/LaunchAgents/com.apple.SafariLaunchAgent.plist" || recs[0]["Domain"] != "system" {
		t.Fatalf("linked job: %v", recs[0])
	}
	// not a dictionary at all
	var buf bytes.Buffer
	if _, err := parseByFamily(strings.NewReader(`<plist version="1.0"><array/></plist>`), "job", "Library/LaunchAgents/x.plist", record.NewWriter(&buf)); err == nil {
		t.Fatal("a non-dictionary plist must error")
	}
}

func TestOverrides(t *testing.T) {
	recs := parseTo(t, "override", "private/var/db/com.apple.xpc.launchd/disabled.501.plist",
		`<plist version="1.0"><dict><key>com.apple.Siri.agent</key><false/><key>com.apple.ftpd</key><true/></dict></plist>`)
	if len(recs) != 2 {
		t.Fatalf("%d records", len(recs))
	}
	if recs[0]["RecordType"] != "launchd_override" || recs[0]["Label"] != "com.apple.Siri.agent" || recs[0]["Disabled"] != false || recs[0]["OverrideUID"] != float64(501) {
		t.Fatalf("row 0: %v", recs[0])
	}
	if recs[1]["Label"] != "com.apple.ftpd" || recs[1]["Disabled"] != true {
		t.Fatalf("row 1: %v", recs[1])
	}
}
