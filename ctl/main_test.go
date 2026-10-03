package ctl

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Get-Sybers/gopinfo/record"
)

func parse(t *testing.T, family, sc, content string) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseByFamily(strings.NewReader(content), family, sc, w); err != nil {
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

func TestSysctl(t *testing.T) {
	recs := parse(t, "sysctl", "admin",
		"# comment\nnet.ipv4.ip_forward = 1\nkernel.yama.ptrace_scope=0\n-net.core.bpf_jit_enable = 2\n")
	if len(recs) != 3 {
		t.Fatalf("count %d", len(recs))
	}
	if recs[0]["Parameter"] != "net.ipv4.ip_forward" || recs[0]["Value"] != "1" ||
		recs[0]["Scope"] != "admin" {
		t.Fatalf("param: %v", recs[0])
	}
	if recs[1]["Parameter"] != "kernel.yama.ptrace_scope" || recs[1]["Value"] != "0" {
		t.Fatalf("no-space form: %v", recs[1])
	}
	if recs[2]["Parameter"] != "net.core.bpf_jit_enable" || !strings.HasPrefix(recs[2]["Raw"].(string), "-") {
		t.Fatalf("dash form: %v", recs[2])
	}
}

func TestModules(t *testing.T) {
	recs := parse(t, "modules_load", "vendor", "br_netfilter\noverlay\n")
	if len(recs) != 2 || recs[0]["Module"] != "br_netfilter" || recs[0]["Scope"] != "vendor" {
		t.Fatalf("modules-load: %v", recs)
	}

	content := "blacklist pcspkr\noptions snd_hda_intel power_save=1\ninstall examplemod /bin/true\nalias net-pf-31 off\n"
	recs = parse(t, "modprobe", "admin", content)
	if recs[0]["Directive"] != "blacklist" || recs[0]["Module"] != "pcspkr" {
		t.Fatalf("blacklist: %v", recs[0])
	}
	if recs[1]["Directive"] != "options" || recs[1]["Value"] != "power_save=1" {
		t.Fatalf("options: %v", recs[1])
	}
	if recs[2]["Directive"] != "install" || recs[2]["Module"] != "examplemod" ||
		recs[2]["Value"] != "/bin/true" {
		t.Fatalf("install: %v", recs[2])
	}
	if recs[3]["Directive"] != "alias" || recs[3]["Value"] != "off" {
		t.Fatalf("alias: %v", recs[3])
	}
}

func TestLoader(t *testing.T) {
	recs := parse(t, "ld_preload", "admin", "/usr/lib/libexample.so /opt/lib/libother.so\n")
	if len(recs) != 2 || recs[0]["Library"] != "/usr/lib/libexample.so" ||
		recs[1]["Library"] != "/opt/lib/libother.so" {
		t.Fatalf("preload: %v", recs)
	}

	recs = parse(t, "ld_conf", "admin", "include /etc/ld.so.conf.d/*.conf\n/opt/custom/lib\n")
	if recs[0]["Include"] != "/etc/ld.so.conf.d/*.conf" || recs[1]["Path"] != "/opt/custom/lib" {
		t.Fatalf("ld_conf: %v", recs)
	}
}

func TestClassifyAndScope(t *testing.T) {
	cases := map[string]string{
		"etc/sysctl.conf":                  "sysctl",
		"etc/sysctl.d/99-custom.conf":      "sysctl",
		"usr/lib/sysctl.d/50-default.conf": "sysctl",
		"etc/modules":                      "modules_load",
		"etc/modules-load.d/k8s.conf":      "modules_load",
		"etc/modprobe.d/blacklist.conf":    "modprobe",
		"etc/ld.so.preload":                "ld_preload",
		"etc/ld.so.conf":                   "ld_conf",
		"etc/ld.so.conf.d/libc.conf":       "ld_conf",
		"etc/passwd":                       "",
		"home/alice/modules":               "",
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
	if scope("etc/sysctl.d/x.conf") != "admin" || scope("usr/lib/sysctl.d/x.conf") != "vendor" ||
		scope("run/sysctl.d/x.conf") != "runtime" {
		t.Fatal("scope wrong")
	}
}
