package host

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/get-sybers/gopinfo/record"
)

func TestLocaltimeSymlinkText(t *testing.T) {
	var buf bytes.Buffer
	w := record.NewWriter(&buf)
	n, err := parseByFamily(strings.NewReader("/var/db/timezone/zoneinfo/Europe/Tallinn"), "localtime", w)
	w.Flush()
	if err != nil || n != 1 {
		t.Fatalf("%d rows, %v", n, err)
	}
	var rec map[string]any
	json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec)
	if rec["RecordType"] != "timezone" || rec["Timezone"] != "Europe/Tallinn" {
		t.Fatalf("%v", rec)
	}
	if _, err := parseByFamily(strings.NewReader("garbage"), "localtime", record.NewWriter(&buf)); err == nil {
		t.Fatal("neither TZif nor a zoneinfo path must error")
	}
}
