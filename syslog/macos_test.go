package syslog

import (
	"strings"
	"testing"
	"time"
)

func TestMacOSLogDialects(t *testing.T) {
	ref := time.Date(2024, 4, 6, 0, 0, 0, 0, time.UTC)
	var rec syslogRecord
	// install.log: ISO with a two-digit zone offset
	parseLine("2023-06-11 18:07:13+00 localhost opendirectoryd[195]: opendirectoryd (build 483.250) launched - installer mode", ref, time.UTC, &rec)
	if rec.EventTime != "2023-06-11T18:07:13.000000Z" || rec.Hostname != "localhost" || rec.Ident != "opendirectoryd" || rec.PID == nil || *rec.PID != 195 {
		t.Fatalf("install.log: %+v", rec)
	}
	rec = syslogRecord{}
	parseLine("2024-03-01 12:00:00+02 Georgs-MacBook-Air softwareupdated[400]: done", ref, time.UTC, &rec)
	if rec.EventTime != "2024-03-01T10:00:00.000000Z" {
		t.Fatalf("offset +02: %+v", rec)
	}
	// system.log: plain BSD
	rec = syslogRecord{}
	parseLine("Apr  6 08:39:20 Georgs-MacBook-Air syslogd[105]: ASL Sender Statistics", ref, time.UTC, &rec)
	if rec.Hostname != "Georgs-MacBook-Air" || rec.Ident != "syslogd" || !strings.HasPrefix(rec.EventTime, "2024-04-06T08:39:20") {
		t.Fatalf("system.log: %+v", rec)
	}
	// wifi.log: weekday, milliseconds, the sender in angle brackets
	rec = syslogRecord{}
	parseLine("Fri Mar  1 00:50:11.543 <kernel> AirPort_Brcm43xx::platformWoWEnable: WWEN[disable], in_fatal_err[0]", ref, time.UTC, &rec)
	if rec.EventTime != "2024-03-01T00:50:11.543000Z" || rec.Ident != "kernel" || !strings.HasPrefix(rec.Message, "AirPort_Brcm43xx") || rec.Hostname != "" {
		t.Fatalf("wifi.log: %+v", rec)
	}
	rec = syslogRecord{}
	parseLine("Fri Mar  1 00:50:56.344 <airportd[123]> wl0: TCPKEEP", ref, time.UTC, &rec)
	if rec.Ident != "airportd[123]" || rec.Message != "wl0: TCPKEEP" {
		t.Fatalf("wifi.log ident: %+v", rec)
	}
	for _, name := range []string{"system.log", "system.log.2.gz", "install.log", "wifi.log", "wifi.log.0.bz2", "fsck_apfs.log"} {
		if !isSyslogFile("private/var/log/" + name) {
			t.Errorf("%s not discovered", name)
		}
	}
	if isSyslogFile("private/var/log/daily.out") {
		t.Error("daily.out is not a syslog stream")
	}
}
