package host

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

func TestOsReleaseAndOneLiners(t *testing.T) {
	recs := parse(t, "os_release",
		"NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"13\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nHOME_URL=\"https://www.debian.org/\"\n")
	r := recs[0]
	if r["Name"] != "Debian GNU/Linux" || r["ID"] != "debian" || r["VersionID"] != "13" {
		t.Fatalf("os-release: %v", r)
	}
	if r["Fields"].(map[string]any)["HOME_URL"] != "https://www.debian.org/" {
		t.Fatalf("fields: %v", r)
	}

	if r := parse(t, "hostname", "web01.internal.example\n")[0]; r["Hostname"] != "web01.internal.example" {
		t.Fatalf("hostname: %v", r)
	}
	if r := parse(t, "machine_id", "0123456789abcdef0123456789abcdef\n")[0]; r["MachineID"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("machine-id: %v", r)
	}
	if r := parse(t, "timezone", "Europe/Berlin\n")[0]; r["Timezone"] != "Europe/Berlin" {
		t.Fatalf("timezone: %v", r)
	}
	if r := parse(t, "locale", "LANG=en_US.UTF-8\n")[0]; r["Lang"] != "en_US.UTF-8" {
		t.Fatalf("locale: %v", r)
	}

	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseOneLiner(strings.NewReader("not hex!\n"), "machine_id", w); err == nil {
		t.Fatal("bad machine-id accepted")
	}
}

func TestTZif(t *testing.T) {
	img := append([]byte("TZif2"), make([]byte, 60)...)
	img = append(img, []byte("\nCET-1CEST,M3.5.0,M10.5.0/3\n")...)
	recs := parse(t, "localtime", string(img))
	if recs[0]["PosixTZ"] != "CET-1CEST,M3.5.0,M10.5.0/3" {
		t.Fatalf("tzif: %v", recs[0])
	}
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	if _, err := parseTZif(strings.NewReader("plain text"), w); err == nil {
		t.Fatal("non-TZif accepted")
	}
}

func TestFstab(t *testing.T) {
	recs := parse(t, "fstab",
		"# static file system information\n"+
			"UUID=9f8e7d6c-1a2b-3c4d-5e6f-708192a3b4c5 / ext4 errors=remount-ro 0 1\n"+
			"LABEL=data /data xfs noatime 0 2\n"+
			"/dev/mapper/vg0-home /home ext4 defaults 0 2\n"+
			"backup01:/exports/share /mnt/share nfs ro 0 0\n")
	if len(recs) != 4 {
		t.Fatalf("count %d", len(recs))
	}
	root := recs[0]
	if root["SpecType"] != "uuid" || root["UUID"] != "9f8e7d6c-1a2b-3c4d-5e6f-708192a3b4c5" ||
		root["MountPoint"] != "/" || root["FSType"] != "ext4" || root["Pass"] != "1" {
		t.Fatalf("uuid row: %v", root)
	}
	if recs[1]["SpecType"] != "label" || recs[1]["Label"] != "data" {
		t.Fatalf("label row: %v", recs[1])
	}
	if recs[2]["SpecType"] != "path" || recs[2]["Device"] != "/dev/mapper/vg0-home" {
		t.Fatalf("path row: %v", recs[2])
	}
	if recs[3]["SpecType"] != "remote" || recs[3]["MountPoint"] != "/mnt/share" {
		t.Fatalf("remote row: %v", recs[3])
	}
}

func TestCrypttab(t *testing.T) {
	recs := parse(t, "crypttab",
		"cryptroot UUID=00112233-4455-6677-8899-aabbccddeeff none luks,discard\n")
	r := recs[0]
	if r["MapperName"] != "cryptroot" || r["SpecType"] != "uuid" ||
		r["UUID"] != "00112233-4455-6677-8899-aabbccddeeff" ||
		r["KeyFile"] != nil || r["Options"] != "luks,discard" {
		t.Fatalf("crypttab: %v", r)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"etc/os-release":      "os_release",
		"usr/lib/os-release":  "os_release",
		"etc/hostname":        "hostname",
		"etc/machine-id":      "machine_id",
		"etc/timezone":        "timezone",
		"etc/localtime":       "localtime",
		"etc/locale.conf":     "locale",
		"etc/default/locale":  "locale",
		"etc/fstab":           "fstab",
		"etc/crypttab":        "crypttab",
		"etc/passwd":          "",
		"home/alice/hostname": "",
		"var/log/syslog":      "",
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}
