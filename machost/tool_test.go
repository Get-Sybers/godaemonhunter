package machost

import (
	"bytes"
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
		"System/Library/CoreServices/SystemVersion.plist":           "os_release",
		"Library/Preferences/SystemConfiguration/preferences.plist": "hostname",
		"Library/Preferences/.GlobalPreferences.plist":              "globalprefs",
		"Users/gl/Library/Preferences/.GlobalPreferences.plist":     "",
		"Library/Preferences/preferences.plist":                     "",
		"System/Library/CoreServices/SystemVersion.txt":             "",
	}
	for rel, want := range cases {
		if got := classify(rel); got != want {
			t.Errorf("%s: %q, want %q", rel, got, want)
		}
	}
}

func TestSystemVersion(t *testing.T) {
	recs := parseTo(t, "os_release", `<plist version="1.0"><dict>
		<key>ProductBuildVersion</key><string>21H1015</string>
		<key>ProductCopyright</key><string>1983-2024 Apple Inc.</string>
		<key>ProductName</key><string>macOS</string>
		<key>ProductUserVisibleVersion</key><string>12.7.3</string>
		<key>ProductVersion</key><string>12.7.3</string>
		<key>iOSSupportVersion</key><string>15.7</string>
	</dict></plist>`)
	r := recs[0]
	if r["RecordType"] != "os_release" || r["Name"] != "macOS" || r["ID"] != "macos" || r["VersionID"] != "12.7.3" || r["PrettyName"] != "macOS 12.7.3 (21H1015)" {
		t.Fatalf("os_release: %v", r)
	}
	if f, _ := r["Fields"].(map[string]any); f["iOSSupportVersion"] != "15.7" {
		t.Fatalf("fields: %v", r["Fields"])
	}
}

func TestPreferencesAndGlobalPrefs(t *testing.T) {
	recs := parseTo(t, "hostname", `<plist version="1.0"><dict>
		<key>Model</key><string>MacBookAir7,2</string>
		<key>System</key><dict>
			<key>Network</key><dict><key>HostNames</key><dict><key>LocalHostName</key><string>Georgs-MacBook-Air</string></dict></dict>
			<key>System</key><dict><key>ComputerName</key><string>Georg’s MacBook Air</string><key>HostName</key><string>gl-mba.local</string></dict>
		</dict>
	</dict></plist>`)
	r := recs[0]
	if r["RecordType"] != "hostname" || r["Hostname"] != "gl-mba.local" || r["LocalHostName"] != "Georgs-MacBook-Air" || r["ComputerName"] != "Georg’s MacBook Air" || r["Model"] != "MacBookAir7,2" {
		t.Fatalf("hostname: %v", r)
	}
	// without HostName the local host name stands in
	recs = parseTo(t, "hostname", `<plist version="1.0"><dict><key>System</key><dict><key>System</key><dict><key>LocalHostName</key><string>mba</string></dict></dict></dict></plist>`)
	if recs[0]["Hostname"] != "mba" {
		t.Fatalf("fallback: %v", recs[0])
	}
	recs = parseTo(t, "globalprefs", `<plist version="1.0"><dict>
		<key>AppleLanguages</key><array><string>en-EE</string></array>
		<key>AppleLocale</key><string>en_EE</string>
		<key>Country</key><string>EE</string>
		<key>com.apple.TimeZonePref.Last_Selected_City</key><array>
			<string>59.43389</string><string>24.72806</string><string>0</string><string>Europe/Tallinn</string><string>EE</string><string>Tallinn</string><string>Estonia</string>
		</array>
	</dict></plist>`)
	if len(recs) != 2 || recs[0]["RecordType"] != "timezone" || recs[0]["Timezone"] != "Europe/Tallinn" || recs[0]["City"] != "Tallinn" {
		t.Fatalf("timezone: %v", recs)
	}
	if recs[1]["RecordType"] != "locale" || recs[1]["Lang"] != "en_EE" || recs[1]["Country"] != "EE" {
		t.Fatalf("locale: %v", recs[1])
	}
	var buf bytes.Buffer
	if _, err := parseByFamily(strings.NewReader(`<plist version="1.0"><dict><key>x</key><string>y</string></dict></plist>`), "globalprefs", record.NewWriter(&buf)); err == nil {
		t.Fatal("a plist without the host keys must error")
	}
}
