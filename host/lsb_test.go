package host

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Get-Sybers/gopinfo/record"
)

// TestLSBReleasePrecedence: etc/lsb-release is the os_release row only when
// the staged tree has no os-release identity — a dangling symlink staged
// as its link text, or no os-release at all. Beside a readable os-release
// it is an lsb_release row, so the knowledge store's OS stays PRETTY_NAME
// (the store keeps the first os_release row in path order, and
// etc_lsb-release sorts first).
func TestLSBReleasePrecedence(t *testing.T) {
	lsb := "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_DESCRIPTION=\"Ubuntu 22.04.4 LTS\"\n"
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no os-release", nil, "os_release"},
		{"dangling symlink staged as its link text", map[string]string{"etc/os-release": "../usr/lib/os-release"}, "os_release"},
		{"os-release without an identity", map[string]string{"etc/os-release": "HOME_URL=\"https://example.org/\"\n"}, "os_release"},
		{"etc/os-release with an identity", map[string]string{"etc/os-release": "PRETTY_NAME=\"Linux Mint 21.3\"\nID=linuxmint\n"}, "lsb_release"},
		{"usr/lib/os-release with an identity", map[string]string{"usr/lib/os-release": "NAME=\"Ubuntu\"\n"}, "lsb_release"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			for rel, body := range c.files {
				p := filepath.Join(root, rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var buf bytes.Buffer
			w := record.NewWriter(&buf)
			if _, err := parseStaged(strings.NewReader(lsb), "lsb_release", root, w); err != nil {
				t.Fatal(err)
			}
			w.Flush()
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.SplitN(strings.TrimSpace(buf.String()), "\n", 2)[0]), &m); err != nil {
				t.Fatal(err)
			}
			if m["RecordType"] != c.want || m["PrettyName"] != "Ubuntu 22.04.4 LTS" {
				t.Errorf("RecordType = %v (want %s), PrettyName = %v", m["RecordType"], c.want, m["PrettyName"])
			}
		})
	}
	// a lone file (no root) keeps its own type
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseStaged(strings.NewReader(lsb), "lsb_release", "", w); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	if !strings.Contains(buf.String(), `"RecordType":"lsb_release"`) {
		t.Errorf("lone lsb-release: %s", buf.String())
	}
}
