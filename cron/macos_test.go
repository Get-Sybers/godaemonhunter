package cron

import "testing"

func TestMacOSFamilies(t *testing.T) {
	cases := map[string][2]string{
		"private/var/at/tabs/gl":                    {"spool", "gl"},
		"private/var/at/jobs/a0001a019f3c2e":        {"at", ""},
		"private/var/at/jobs/.SEQ":                  {"", ""},
		"private/etc/periodic/daily/110.clean-tmps": {"runparts", ""},
		"private/etc/periodic/weekly/320.whatis":    {"runparts", ""},
		"private/etc/periodic.conf":                 {"conf", ""},
		"private/etc/periodic.conf.local":           {"conf", ""},
		"private/etc/crontab":                       {"system", ""},
		"etc/daily/x":                               {"", ""},
	}
	for rel, want := range cases {
		fam, owner := family(rel)
		if fam != want[0] || owner != want[1] {
			t.Errorf("%s: %s/%s, want %s/%s", rel, fam, owner, want[0], want[1])
		}
	}
}
