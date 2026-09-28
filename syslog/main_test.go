package syslog

// main_test.go proves the timestamp dialects, the ident/pid split, and the
// typed families over ordinary log lines.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/get-sybers/gopinfo/record"
)

var ref = time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

func parse(t *testing.T, content string) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseLog(strings.NewReader(content), ref, nil, w); err != nil {
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

func TestDialects(t *testing.T) {
	recs := parse(t,
		"Mar  1 22:14:02 web01 systemd[1]: Started daily apt activities.\n"+
			"2026-03-01T22:14:03.123456+02:00 web01 rsyslogd: rsyslogd was HUPed\n"+
			"<13>1 2026-03-01T20:14:04Z web01 app 4321 - - service started\n"+
			"  continuation detail line\n")
	if len(recs) != 4 {
		t.Fatalf("count %d", len(recs))
	}
	if recs[0]["EventTime"] != "2026-03-01T22:14:02.000000Z" || recs[0]["Hostname"] != "web01" ||
		recs[0]["Ident"] != "systemd" || recs[0]["PID"] != float64(1) {
		t.Fatalf("bsd: %v", recs[0])
	}
	if recs[1]["EventTime"] != "2026-03-01T20:14:03.123456Z" || recs[1]["Ident"] != "rsyslogd" {
		t.Fatalf("iso: %v", recs[1])
	}
	if recs[2]["EventTime"] != "2026-03-01T20:14:04.000000Z" || recs[2]["Ident"] != "app" ||
		recs[2]["PID"] != float64(4321) || recs[2]["Message"] != "service started" {
		t.Fatalf("5424: %v", recs[2])
	}
	if recs[3]["EventTime"] != nil || recs[3]["Message"] != "  continuation detail line" {
		t.Fatalf("continuation: %v", recs[3])
	}
}

func TestTypedFamilies(t *testing.T) {
	fp := "SHA256:AbCdEf0123456789AbCdEf0123456789AbCdEf01234"
	recs := parse(t,
		"Mar  1 22:14:02 web01 sshd[901]: Accepted publickey for alice from 198.51.100.7 port 51234 ssh2: ED25519 "+fp+"\n"+
			"Mar  1 22:14:05 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status nginx\n"+
			"Mar  1 22:15:01 web01 CRON[1002]: (alice) CMD (/home/alice/bin/sync.sh)\n"+
			"Mar  1 22:14:05 web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)\n")
	ssh := recs[0]
	if ssh["RecordType"] != "sshd_event" || ssh["SSHEvent"] != "accepted" ||
		ssh["Method"] != "publickey" || ssh["Username"] != "alice" ||
		ssh["IPAddress"] != "198.51.100.7" || ssh["Port"] != float64(51234) ||
		ssh["KeyType"] != "ED25519" || ssh["Fingerprint"] != fp {
		t.Fatalf("sshd: %v", ssh)
	}
	sudo := recs[1]
	if sudo["RecordType"] != "sudo_event" || sudo["Username"] != "alice" ||
		sudo["TargetUser"] != "root" || sudo["TTY"] != "pts/0" ||
		sudo["Command"] != "/usr/bin/systemctl status nginx" {
		t.Fatalf("sudo: %v", sudo)
	}
	cron := recs[2]
	if cron["RecordType"] != "cron_event" || cron["Username"] != "alice" ||
		cron["Command"] != "/home/alice/bin/sync.sh" {
		t.Fatalf("cron: %v", cron)
	}
	pam := recs[3]
	if pam["RecordType"] != "pam_session" || pam["SessionOp"] != "opened" ||
		pam["Username"] != "root" || pam["ByUser"] != "alice" || pam["ByUID"] != float64(1000) {
		t.Fatalf("pam: %v", pam)
	}
}

func TestIsSyslogFile(t *testing.T) {
	yes := []string{"var/log/syslog", "var/log/syslog.2.gz", "var/log/auth.log.1",
		"var/log/messages-20260301", "var/log/cron", "var/log/kern.log"}
	no := []string{"var/log/wtmp", "etc/rsyslog.conf", "var/log/syslog.conf",
		"var/log/dpkg.log", "home/alice/.bash_history"}
	for _, p := range yes {
		if !isSyslogFile(p) {
			t.Errorf("isSyslogFile(%q) = false", p)
		}
	}
	for _, p := range no {
		if isSyslogFile(p) {
			t.Errorf("isSyslogFile(%q) = true", p)
		}
	}
}

func TestHostZoneApplied(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("zoneinfo unavailable")
	}
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	// winter (CET, +01:00): naive local 22:14:02 == 21:14:02Z
	if _, err := parseLog(strings.NewReader("Jan 10 22:14:02 web01 systemd[1]: Started daily apt activities.\n"),
		time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC), loc, w); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	var m map[string]any
	json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m)
	if m["EventTime"] != "2026-01-10T21:14:02.000000Z" {
		t.Fatalf("zone not applied: %v", m["EventTime"])
	}
}
