package unit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Get-Sybers/gopinfo/record"
)

func parse(t *testing.T, rel, content string) map[string]any {
	t.Helper()
	unit, utype, dropin := classify(rel)
	if unit == "" {
		t.Fatalf("classify(%q) found nothing", rel)
	}
	rec := &unitRecord{Unit: unit, UnitType: utype, DropIn: dropin, Scope: scope(rel)}
	rec.RecordType = "systemd_unit"
	if dropin {
		rec.RecordType = "systemd_dropin"
	}
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseUnit(strings.NewReader(content), rec, w); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	var m map[string]any
	json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m)
	return m
}

const svc = `[Unit]
Description=Totally Legit Service
After=network.target sshd.service
ConditionPathExists=/etc/legit

[Service]
Type=oneshot
User=root
ExecStartPre=/bin/sleep 1
ExecStart=/usr/local/bin/legit \
  --flag value
Environment=FOO=bar
Environment=BAZ=qux

[Install]
WantedBy=multi-user.target
`

func TestServiceUnit(t *testing.T) {
	m := parse(t, "etc/systemd/system/legit.service", svc)
	if m["Unit"] != "legit.service" || m["UnitType"] != "service" || m["Scope"] != "admin" {
		t.Fatalf("identity: %v", m)
	}
	if m["Description"] != "Totally Legit Service" || m["ServiceType"] != "oneshot" || m["User"] != "root" {
		t.Fatalf("fields: %v", m)
	}
	es := m["ExecStart"].([]any)
	if len(es) != 1 || es[0] != "/usr/local/bin/legit --flag value" {
		t.Fatalf("continuation: %v", es)
	}
	env := m["Environment"].([]any)
	if len(env) != 2 || env[1] != "BAZ=qux" {
		t.Fatalf("env accumulate: %v", env)
	}
	if m["WantedBy"].([]any)[0] != "multi-user.target" {
		t.Fatalf("install: %v", m)
	}
	after := m["After"].([]any)
	if len(after) != 2 || after[1] != "sshd.service" {
		t.Fatalf("after: %v", after)
	}
	if !strings.HasPrefix(m["ConditionLines"].([]any)[0].(string), "ConditionPathExists=") {
		t.Fatalf("conditions: %v", m)
	}
}

func TestTimerAndReset(t *testing.T) {
	m := parse(t, "usr/lib/systemd/system/beacon.timer",
		"[Timer]\nOnCalendar=daily\nOnCalendar=\nOnCalendar=*-*-* 03:14:00\nPersistent=true\nUnit=beacon.service\n")
	oc := m["OnCalendar"].([]any)
	if len(oc) != 1 || oc[0] != "*-*-* 03:14:00" { // empty assignment reset the list
		t.Fatalf("reset semantics: %v", oc)
	}
	if m["Persistent"] != "true" || m["TimerUnit"] != "beacon.service" || m["Scope"] != "vendor" {
		t.Fatalf("timer: %v", m)
	}
}

func TestDropin(t *testing.T) {
	m := parse(t, "etc/systemd/system/sshd.service.d/override.conf",
		"[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -o LogLevel=QUIET\n")
	if m["RecordType"] != "systemd_dropin" || m["Unit"] != "sshd.service" || m["DropIn"] != true {
		t.Fatalf("dropin: %v", m)
	}
}

func TestUserScopeAndGarbage(t *testing.T) {
	m := parse(t, "home/alice/.config/systemd/user/sync.service", "[Service]\nExecStart=/home/alice/.local/bin/sync\n")
	if m["Scope"] != "user" {
		t.Fatalf("scope: %v", m)
	}
	rec := &unitRecord{}
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseUnit(strings.NewReader("not a unit file at all\n"), rec, w); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestClassify(t *testing.T) {
	type want struct {
		u, ty string
		d     bool
	}
	cases := map[string]want{
		"etc/systemd/system/x.service":          {"x.service", "service", false},
		"lib/systemd/system/y.timer":            {"y.timer", "timer", false},
		"etc/systemd/system/x.service.d/a.conf": {"x.service", "service", true},
		"etc/systemd/system/x.service.d/a.txt":  {"", "", false},
		"etc/passwd":                            {"", "", false},
		"usr/lib/systemd/system/s.socket":       {"s.socket", "socket", false},
	}
	for in, w := range cases {
		u, ty, d := classify(in)
		if u != w.u || ty != w.ty || d != w.d {
			t.Errorf("classify(%q) = %q,%q,%v want %q,%q,%v", in, u, ty, d, w.u, w.ty, w.d)
		}
	}
}

func TestMountUnit(t *testing.T) {
	m := parse(t, "etc/systemd/system/data.mount",
		"[Unit]\nDescription=Data volume\n[Mount]\nWhat=/dev/disk/by-uuid/9f8e7d6c-1a2b-3c4d-5e6f-708192a3b4c5\nWhere=/data\nType=ext4\nOptions=noatime\n[Install]\nWantedBy=multi-user.target\n")
	if m["UnitType"] != "mount" || m["What"] != "/dev/disk/by-uuid/9f8e7d6c-1a2b-3c4d-5e6f-708192a3b4c5" ||
		m["Where"] != "/data" || m["MountType"] != "ext4" || m["MountOptions"] != "noatime" {
		t.Fatalf("mount unit: %v", m)
	}
	if m["ServiceType"] != nil {
		t.Fatalf("Type leaked into ServiceType: %v", m)
	}
}
