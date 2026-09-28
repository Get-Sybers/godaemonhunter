//go:build ignore

// gen.go writes the godaemonhunter contract-test fixtures into argv[1]:
// Layer-1 material (passwd, hostname, timezone) plus daemon streams
// (an audit event, a syslog line) so a hunt proves the layering.
package main

import (
	"os"
	"path/filepath"
)

func main() {
	d := os.Args[1]
	mk := func(rel, content string) {
		p := filepath.Join(d, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	mk("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\n")
	mk("etc/hostname", "web01\n")
	mk("etc/timezone", "Europe/Berlin\n")
	mk("var/log/audit/audit.log",
		`type=SYSCALL msg=audit(1767225600.123:42): arch=c000003e syscall=59 success=yes exit=0 pid=1201 auid=1000 uid=1000 gid=1000 euid=1000 comm="ls" exe="/usr/bin/ls"`+"\n"+
			`type=EOE msg=audit(1767225600.123:42):`+"\n")
	mk("var/log/syslog", "Jan 10 22:14:02 web01 systemd[1]: Started daily apt activities.\n")
	// a Mac's surface beside it: the same run handles both
	mk("System/Library/CoreServices/SystemVersion.plist", `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>ProductBuildVersion</key><string>21H1015</string><key>ProductName</key><string>macOS</string><key>ProductVersion</key><string>12.7.3</string></dict></plist>
`)
	mk("private/var/db/dslocal/nodes/Default/users/gl.plist", `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>name</key><array><string>gl</string></array><key>uid</key><array><string>501</string></array><key>gid</key><array><string>20</string></array><key>home</key><array><string>/Users/gl</string></array><key>shell</key><array><string>/bin/zsh</string></array></dict></plist>
`)
	mk("Users/gl/Library/LaunchAgents/org.keepassxc.KeePassXC.plist", `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>org.keepassxc.KeePassXC</string><key>ProgramArguments</key><array><string>/Applications/KeePassXC.app/Contents/MacOS/KeePassXC</string></array><key>RunAtLoad</key><true/></dict></plist>
`)
	mk("private/var/log/install.log", "2023-06-11 18:07:13+00 localhost opendirectoryd[195]: opendirectoryd (build 483.250) launched - installer mode\n")
}
