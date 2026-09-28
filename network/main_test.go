package network

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
	if _, err := parseByFamily(strings.NewReader(content), family, w); err != nil {
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

func TestHostsResolvNsswitch(t *testing.T) {
	recs := parse(t, "hosts", "127.0.0.1 localhost\n192.0.2.10 intranet.example intranet # main portal\n")
	if recs[0]["IPAddress"] != "127.0.0.1" || recs[0]["Hostnames"].([]any)[0] != "localhost" {
		t.Fatalf("hosts: %v", recs[0])
	}
	h := recs[1]["Hostnames"].([]any)
	if recs[1]["IPAddress"] != "192.0.2.10" || len(h) != 2 || h[1] != "intranet" {
		t.Fatalf("hosts comment strip: %v", recs[1])
	}

	recs = parse(t, "resolv", "nameserver 192.0.2.53\nsearch example.internal\noptions timeout:2\n")
	if recs[0]["Directive"] != "nameserver" || recs[0]["Value"] != "192.0.2.53" ||
		recs[2]["Value"] != "timeout:2" {
		t.Fatalf("resolv: %v", recs)
	}

	recs = parse(t, "nsswitch", "passwd: files systemd\nhosts: files dns\n")
	src := recs[1]["Sources"].([]any)
	if recs[1]["Database"] != "hosts" || len(src) != 2 || src[1] != "dns" {
		t.Fatalf("nsswitch: %v", recs[1])
	}
}

func TestTCPWrappersAndInterfaces(t *testing.T) {
	recs := parse(t, "tcpwrappers", "sshd : 192.0.2.0/24 : allow\nALL : ALL : deny\n")
	if recs[0]["Daemons"] != "sshd" || recs[0]["Clients"] != "192.0.2.0/24" || recs[0]["Option"] != "allow" {
		t.Fatalf("tcpwrappers: %v", recs[0])
	}

	content := "auto eth0\niface eth0 inet static\n    address 192.0.2.20/24\n    gateway 192.0.2.1\niface eth1 inet dhcp\n"
	recs = parse(t, "interfaces", content)
	if len(recs) != 3 {
		t.Fatalf("count %d: %v", len(recs), recs)
	}
	if recs[0]["RecordType"] != "interfaces_directive" || recs[0]["Directive"] != "auto" || recs[0]["Value"] != "eth0" {
		t.Fatalf("auto: %v", recs[0])
	}
	e0 := recs[1]
	if e0["Interface"] != "eth0" || e0["Method"] != "static" ||
		e0["Fields"].(map[string]any)["address"] != "192.0.2.20/24" {
		t.Fatalf("iface: %v", e0)
	}
	if recs[2]["Method"] != "dhcp" {
		t.Fatalf("dhcp iface: %v", recs[2])
	}
}

func TestProfilesAndFirewall(t *testing.T) {
	nm := "[connection]\nid=Office WiFi\ntype=wifi\nuuid=8a2f0000-1111-2222-3333-444455556666\n[wifi]\nssid=OfficeNet\n[ipv4]\nmethod=auto\n"
	recs := parse(t, "nmconnection", nm)
	r := recs[0]
	if r["RecordType"] != "nmconnection_profile" || r["Name"] != "Office WiFi" ||
		r["ConnType"] != "wifi" || r["SSID"] != "OfficeNet" ||
		r["Fields"].(map[string]any)["ipv4.method"] != "auto" {
		t.Fatalf("nm: %v", r)
	}

	nw := "[Match]\nName=eth0\n[Network]\nAddress=192.0.2.20/24\nDNS=192.0.2.53\n"
	recs = parse(t, "networkd", nw)
	if recs[0]["Interface"] != "eth0" || recs[0]["Fields"].(map[string]any)["Network.Address"] != "192.0.2.20/24" {
		t.Fatalf("networkd: %v", recs[0])
	}

	ipt := "*filter\n:INPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"
	recs = parse(t, "iptables", ipt)
	if len(recs) != 3 || recs[0]["RecordType"] != "iptables_chain" ||
		recs[0]["Chain"] != "INPUT" || recs[0]["Policy"] != "DROP" || recs[0]["Table"] != "filter" {
		t.Fatalf("chain: %v", recs)
	}
	if recs[1]["RecordType"] != "iptables_rule" || recs[1]["Chain"] != "INPUT" ||
		recs[1]["Rule"] != "-A INPUT -i lo -j ACCEPT" {
		t.Fatalf("rule: %v", recs[1])
	}

	recs = parse(t, "netplan", "network:\n  version: 2\n")
	if recs[0]["RecordType"] != "netplan_config" || !strings.Contains(recs[0]["Config"].(string), "version: 2") {
		t.Fatalf("netplan: %v", recs[0])
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"etc/hosts":                          "hosts",
		"etc/resolv.conf":                    "resolv",
		"etc/nsswitch.conf":                  "nsswitch",
		"etc/hosts.allow":                    "tcpwrappers",
		"etc/network/interfaces":             "interfaces",
		"etc/network/interfaces.d/eth0":      "interfaces",
		"etc/systemd/network/10-lan.network": "networkd",
		"etc/NetworkManager/system-connections/a.nmconnection": "nmconnection",
		"etc/netplan/01-config.yaml":                           "netplan",
		"etc/iptables/rules.v4":                                "iptables",
		"etc/nftables.conf":                                    "nftables",
		"home/alice/hosts":                                     "",
		"etc/passwd":                                           "",
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}
