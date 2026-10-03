package users

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Get-Sybers/gopinfo/record"
)

func TestMasterPasswd(t *testing.T) {
	if classify("private/etc/master.passwd") != "master_passwd" {
		t.Fatal("master.passwd not classified")
	}
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	n, err := parseFile(strings.NewReader("# comment\nnobody:*:-2:-2::0:0:Unprivileged User:/var/empty:/usr/bin/false\nroot:*:0:0::1709288298:0:System Administrator:/var/root:/bin/sh\n"), "master_passwd", w, func(string, ...interface{}) {})
	w.Flush()
	if err != nil || n != 2 {
		t.Fatalf("%d rows, %v", n, err)
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	var nobody, root map[string]any
	json.Unmarshal(lines[0], &nobody)
	json.Unmarshal(lines[1], &root)
	if nobody["RecordType"] != "account" || nobody["Username"] != "nobody" || nobody["UID"] != float64(-2) || nobody["GECOS"] != "Unprivileged User" || nobody["Shell"] != "/usr/bin/false" || nobody["HomeDir"] != "/var/empty" {
		t.Fatalf("nobody: %v", nobody)
	}
	if root["UID"] != float64(0) || root["EventTime"] != "2024-03-01T10:18:18.000000Z" || root["TimeKind"] != "password_change" {
		t.Fatalf("root: %v", root)
	}
}
