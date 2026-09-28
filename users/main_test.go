package users

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/get-sybers/gopinfo/record"
)

func parse(t *testing.T, family, content string) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	n, err := parseFile(strings.NewReader(content), family, w, func(string, ...interface{}) {})
	if err != nil {
		t.Fatalf("%s: %v", family, err)
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
	if len(out) != n {
		t.Fatalf("count mismatch %d vs %d", len(out), n)
	}
	return out
}

func TestPasswdShadowGroup(t *testing.T) {
	recs := parse(t, "passwd", "root:x:0:0:root:/root:/bin/bash\n# comment\nalice:x:1000:1000:Alice:/home/alice:/bin/zsh\n")
	if len(recs) != 2 || recs[0]["Username"] != "root" || recs[0]["UID"] != float64(0) ||
		recs[1]["Shell"] != "/bin/zsh" || recs[0]["RecordType"] != "account" {
		t.Fatalf("passwd: %v", recs)
	}

	recs = parse(t, "shadow", "alice:$y$j9T$abc$def:20454:0:99999:7:::\nlocked:!:20000::::::\n")
	if recs[0]["PasswordCrypt"] != "$y$j9T$abc$def" || recs[0]["EventTime"] != "2026-01-01T00:00:00.000000Z" ||
		recs[0]["TimeKind"] != "password_change" || recs[0]["MaxDays"] != float64(99999) {
		t.Fatalf("shadow: %v", recs[0])
	}
	if recs[1]["PasswordCrypt"] != "!" {
		t.Fatalf("locked crypt not verbatim: %v", recs[1])
	}

	recs = parse(t, "group", "sudo:x:27:alice,bob\n")
	m := recs[0]["Members"].([]any)
	if recs[0]["GroupName"] != "sudo" || len(m) != 2 || m[1] != "bob" {
		t.Fatalf("group: %v", recs[0])
	}
}

func TestSudoers(t *testing.T) {
	content := "# comment\nDefaults env_reset\nUser_Alias ADMINS = alice, bob\n" +
		"%sudo ALL=(ALL:ALL) ALL\nalice ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx, /bin/true\n" +
		"#includedir /etc/sudoers.d\n"
	recs := parse(t, "sudoers", content)
	if len(recs) != 5 {
		t.Fatalf("count: %d %v", len(recs), recs)
	}
	if recs[0]["RecordType"] != "sudoers_default" || recs[0]["Parameters"] != "env_reset" {
		t.Fatalf("defaults: %v", recs[0])
	}
	if recs[1]["RecordType"] != "sudoers_alias" || recs[1]["AliasName"] != "ADMINS" {
		t.Fatalf("alias: %v", recs[1])
	}
	rule := recs[3]
	if rule["RecordType"] != "sudoers_rule" || rule["RunAs"] != "root" {
		t.Fatalf("rule: %v", rule)
	}
	if tags := rule["Tags"].([]any); tags[0] != "NOPASSWD" {
		t.Fatalf("tags: %v", rule)
	}
	if cmds := rule["Commands"].([]any); len(cmds) != 2 || cmds[0] != "/usr/bin/systemctl restart nginx" {
		t.Fatalf("commands: %v", rule)
	}
	if recs[4]["RecordType"] != "sudoers_include" || recs[4]["Include"] != "/etc/sudoers.d" {
		t.Fatalf("include: %v", recs[4])
	}
}

func TestSSHFiles(t *testing.T) {
	// a real-shaped ed25519 key blob (base64 of arbitrary-but-decodable bytes)
	blob := "AAAAC3NzaC1lZDI1NTE5AAAAIGRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVm"
	recs := parse(t, "authorized_keys",
		`command="/usr/bin/rrsync /backup",no-pty ssh-ed25519 `+blob+" backup@host\n"+
			"ssh-ed25519 "+blob+"\n")
	if recs[0]["Options"] != `command="/usr/bin/rrsync /backup",no-pty` ||
		recs[0]["KeyType"] != "ssh-ed25519" || recs[0]["Comment"] != "backup@host" {
		t.Fatalf("authorized_key: %v", recs[0])
	}
	fp := recs[0]["Fingerprint"].(string)
	if !strings.HasPrefix(fp, "SHA256:") || strings.HasSuffix(fp, "=") {
		t.Fatalf("fingerprint: %q", fp)
	}
	if recs[1]["Fingerprint"] != fp {
		t.Fatal("same key, different fingerprint")
	}

	recs = parse(t, "known_hosts",
		"|1|hashhash|morehash ssh-ed25519 "+blob+"\n@revoked badhost ssh-ed25519 "+blob+"\n")
	if recs[0]["Hashed"] != true || recs[1]["Marker"] != "@revoked" || recs[1]["HostPattern"] != "badhost" {
		t.Fatalf("known_hosts: %v", recs)
	}

	recs = parse(t, "sshd_config",
		"PermitRootLogin no\nMatch User git\nPasswordAuthentication no\n")
	if recs[0]["Keyword"] != "PermitRootLogin" || recs[0]["Value"] != "no" {
		t.Fatalf("sshd 1: %v", recs[0])
	}
	if recs[2]["MatchContext"] != "User git" {
		t.Fatalf("match context: %v", recs[2])
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"etc/passwd": "passwd", "etc/shadow": "shadow", "etc/group": "group",
		"etc/sudoers": "sudoers", "etc/sudoers.d/90-cloud": "sudoers",
		"etc/ssh/sshd_config": "sshd_config", "etc/ssh/sshd_config.d/10-x.conf": "sshd_config",
		"home/alice/.ssh/authorized_keys": "authorized_keys",
		"home/alice/.ssh/known_hosts":     "known_hosts",
		"etc/passwd-":                     "passwd",
		"etc/group.conf":                  "", "var/log/syslog": "", "etc/ssh/ssh_config": "",
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGarbageYieldsError(t *testing.T) {
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseFile(strings.NewReader("no colons here\nat all\n"), "passwd", w,
		func(string, ...interface{}) {}); err == nil {
		t.Fatal("garbage passwd accepted")
	}
}
