package macusers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/get-sybers/gopinfo/record"
)

func parseTo(t *testing.T, family, content string) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseByFamily(strings.NewReader(content), family, w); err != nil {
		t.Fatal(err)
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

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"private/var/db/dslocal/nodes/Default/users/gl.plist":     "account",
		"private/var/db/dslocal/nodes/Default/groups/admin.plist": "group",
		"var/db/dslocal/nodes/Default/users/_amavisd.plist":       "account",
		"private/var/db/dslocal/nodes/Default/users/gl.txt":       "",
		"Library/Preferences/users/x.plist":                       "",
	}
	for rel, want := range cases {
		if got := classify(rel); got != want {
			t.Errorf("%s: %q, want %q", rel, got, want)
		}
	}
}

func TestAccount(t *testing.T) {
	// the account policy blob is itself a plist inside a data attribute
	policy := base64.StdEncoding.EncodeToString([]byte(`<plist version="1.0"><dict>
		<key>creationTime</key><real>1708527967.6681762</real>
		<key>failedLoginCount</key><integer>2</integer>
		<key>failedLoginTimestamp</key><real>1709000000</real>
		<key>passwordLastSetTime</key><real>1709288298.372935</real>
	</dict></plist>`))
	recs := parseTo(t, "account", `<plist version="1.0"><dict>
		<key>name</key><array><string>gl</string><string>georg</string></array>
		<key>uid</key><array><string>501</string></array>
		<key>gid</key><array><string>20</string></array>
		<key>home</key><array><string>/Users/gl</string></array>
		<key>shell</key><array><string>/bin/bash</string></array>
		<key>realname</key><array><string>Georg L</string></array>
		<key>generateduid</key><array><string>4508EE9C-084B-4BA8-842E-4A2434933DDF</string></array>
		<key>authentication_authority</key><array><string>;ShadowHash;HASHLIST:&lt;SALTED-SHA512-PBKDF2&gt;</string><string>;SecureToken;</string></array>
		<key>ShadowHashData</key><array><data>AQID</data></array>
		<key>IsHidden</key><array><string>1</string></array>
		<key>accountPolicyData</key><array><data>`+policy+`</data></array>
	</dict></plist>`)
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	r := recs[0]
	if r["RecordType"] != "account" || r["Username"] != "gl" || r["UID"] != float64(501) || r["GID"] != float64(20) || r["HomeDir"] != "/Users/gl" || r["Shell"] != "/bin/bash" || r["GECOS"] != "Georg L" {
		t.Fatalf("account: %v", r)
	}
	if r["HasShadowHash"] != true || r["IsHidden"] != true || r["GeneratedUID"] != "4508EE9C-084B-4BA8-842E-4A2434933DDF" {
		t.Fatalf("flags: %v", r)
	}
	if aa, _ := r["AuthenticationAuthority"].([]any); len(aa) != 2 || aa[1] != ";SecureToken;" {
		t.Fatalf("authority: %v", r["AuthenticationAuthority"])
	}
	if al, _ := r["Aliases"].([]any); len(al) != 1 || al[0] != "georg" {
		t.Fatalf("aliases: %v", r["Aliases"])
	}
	if r["PasswordLastSet"] != "2024-03-01T10:18:18.372935Z" || r["EventTime"] != r["PasswordLastSet"] || r["TimeKind"] != "password_change" {
		t.Fatalf("password time: %v %v %v", r["PasswordLastSet"], r["EventTime"], r["TimeKind"])
	}
	if !strings.HasPrefix(r["AccountCreated"].(string), "2024-02-21T") || r["FailedLoginCount"] != float64(2) || !strings.HasPrefix(r["FailedLoginTime"].(string), "2024-02-27T") {
		t.Fatalf("policy: %v", r)
	}
	if _, has := r["ShadowHashData"]; has {
		t.Fatal("the hash blob must never be carried")
	}
}

func TestGroup(t *testing.T) {
	recs := parseTo(t, "group", `<plist version="1.0"><dict>
		<key>name</key><array><string>admin</string><string>BUILTIN\Administrators</string></array>
		<key>gid</key><array><string>80</string></array>
		<key>realname</key><array><string>Administrators</string></array>
		<key>users</key><array><string>root</string><string>gl</string></array>
		<key>groupmembers</key><array><string>FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000</string></array>
		<key>smb_sid</key><array><string>S-1-5-32-544</string></array>
	</dict></plist>`)
	r := recs[0]
	if r["RecordType"] != "group" || r["GroupName"] != "admin" || r["GID"] != float64(80) || r["SMBSID"] != "S-1-5-32-544" {
		t.Fatalf("group: %v", r)
	}
	if m, _ := r["Members"].([]any); len(m) != 2 || m[1] != "gl" {
		t.Fatalf("members: %v", r["Members"])
	}
	var buf bytes.Buffer
	if _, err := parseByFamily(strings.NewReader(`<plist version="1.0"><dict><key>x</key><string>y</string></dict></plist>`), "group", record.NewWriter(&buf)); err == nil {
		t.Fatal("a record without a name must error")
	}
}
