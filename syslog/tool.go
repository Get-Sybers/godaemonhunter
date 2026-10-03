// gosyslog — syslog-family text log parser for the DX_DFIR pipeline
// (docs/linux §4). Finds the classic text logs under the input tree —
// syslog, messages, auth.log, secure, kern.log, cron, daemon.log, mail.log,
// user.log, debug — rotations and gzip included, and emits one record per
// line with the timestamp dialects normalised (RFC3164 yearless with
// mtime-anchored year inference, ISO-8601, RFC5424).
//
// Rule-1/2 alignment (docs/linux §4.1): known high-value line families are
// TYPED BY THE PARSER — sshd authentication lines, sudo command lines, pam
// session open/close, and cron job lines each get their own RecordType with
// parsed fields — because byakugan's maps select rows with predicates over
// typed fields and never regex raw messages. The raw line always rides
// along; everything else stays a plain syslog_line. Yearless timestamps are
// recorded naive-as-UTC (the imaged host's zone is byakugan-side context).
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOSYSLOG_* environment. The argv flags are the
// debug pass-through:
//
//	gosyslog -f FILE | -d DIR [-q]
package syslog

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Get-Sybers/gopinfo/batch"
	"github.com/Get-Sybers/gopinfo/discover"
	"github.com/Get-Sybers/gopinfo/families"
	"github.com/Get-Sybers/gopinfo/record"
	"github.com/Get-Sybers/gopinfo/tstamp"
)

// syslogRecord is one log line; RecordType is syslog_line or a typed
// family (sshd_event, sudo_event, pam_session, cron_event).
type syslogRecord struct {
	record.Envelope
	Hostname string `json:"Hostname,omitempty"` // the line's own host field (Host is the envelope's knowledge block)
	Ident    string `json:"Ident,omitempty"`
	PID      *int64 `json:"PID,omitempty"`
	Message  string `json:"Message"`
	// the typed families (docs/linux §4.1 rule 1), recognised by the shared
	// pinfo/families engine — the same engine the journal pathway feeds
	families.Typed
	Line int    `json:"Line"`
	Raw  string `json:"Raw"`
}

// ---- discovery -------------------------------------------------------------

var logBases = []string{
	"syslog", "messages", "auth.log", "secure", "kern.log", "cron",
	"cron.log", "daemon.log", "mail.log", "user.log", "debug", "boot.log",
	// macOS: the ASL-fed system log, the installer log, the Wi-Fi daemon's
	// log and the boot-time filesystem checks
	"system.log", "install.log", "wifi.log", "fsck_hfs.log", "fsck_apfs.log",
}

func isSyslogFile(rel string) bool {
	base := strings.ToLower(filepath.Base(rel))
	for _, b := range logBases {
		if discover.Rotated(base, b) {
			return true
		}
	}
	return false
}

// ---- line prefix parsing ---------------------------------------------------

var (
	// "Mar  1 22:14:02 host tail" (RFC3164, no year)
	bsdRe = regexp.MustCompile(`^([A-Z][a-z]{2} [ 0-9]\d \d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$`)
	// "2026-03-01T22:14:02.123456+02:00 host tail" (ISO-8601 prefix)
	isoRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}(?::?\d{2})?)?)\s+(\S+)\s+(.*)$`)
	// "Fri Mar  1 00:50:11.543 <kernel> tail" (macOS wifi.log: weekday, BSD stamp with milliseconds, the sender in angle brackets)
	wifiRe = regexp.MustCompile(`^[A-Z][a-z]{2} ([A-Z][a-z]{2} [ 0-9]\d \d{2}:\d{2}:\d{2})\.(\d{1,6})\s+(<[^>]+>|\S+)\s+(.*)$`)
	// "<13>1 2026-03-01T22:14:02Z host app pid msgid [sd] msg" (RFC5424)
	r5424Re = regexp.MustCompile(`^<\d{1,3}>\d\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+(?:\[[^\]]*\]|-)\s*(.*)$`)
	identRe = regexp.MustCompile(`^([^\s:\[\]]+)(?:\[(\d+)\])?:\s?(.*)$`)
)

// splitIdent splits "ident[pid]: message" off the line tail.
func splitIdent(tail string, rec *syslogRecord) {
	if m := identRe.FindStringSubmatch(tail); m != nil {
		rec.Ident = m[1]
		if m[2] != "" {
			if n, err := strconv.ParseInt(m[2], 10, 64); err == nil {
				rec.PID = &n
			}
		}
		rec.Message = m[3]
		return
	}
	rec.Message = tail
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// parseLine fills one record from a raw line; ref anchors yearless stamps.
func parseLine(line string, ref time.Time, loc *time.Location, rec *syslogRecord) {
	rec.Raw = line
	switch {
	case r5424Re.MatchString(line):
		m := r5424Re.FindStringSubmatch(line)
		if t, ok := tstamp.Flexible(m[1]); ok {
			rec.EventTime = tstamp.ISO8601(t)
			rec.TimeKind = "event"
		}
		rec.Hostname = dash(m[2])
		rec.Ident = dash(m[3])
		if m[4] != "-" {
			if n, err := strconv.ParseInt(m[4], 10, 64); err == nil {
				rec.PID = &n
			}
		}
		rec.Message = m[5]
	case isoRe.MatchString(line):
		m := isoRe.FindStringSubmatch(line)
		if t, ok := tstamp.FlexibleIn(m[1], loc); ok {
			rec.EventTime = tstamp.ISO8601(t)
			rec.TimeKind = "event"
		}
		rec.Hostname = m[2]
		splitIdent(m[3], rec)
	case bsdRe.MatchString(line):
		m := bsdRe.FindStringSubmatch(line)
		if t, ok := tstamp.Syslog3164In(m[1], ref, loc); ok {
			rec.EventTime = tstamp.ISO8601(t)
			rec.TimeKind = "event"
		}
		rec.Hostname = m[2]
		splitIdent(m[3], rec)
	case wifiRe.MatchString(line):
		m := wifiRe.FindStringSubmatch(line)
		if t, ok := tstamp.Syslog3164In(m[1], ref, loc); ok {
			frac := m[2]
			for len(frac) < 9 {
				frac += "0"
			}
			if ns, err := strconv.Atoi(frac); err == nil {
				t = t.Add(time.Duration(ns))
			}
			rec.EventTime = tstamp.ISO8601(t)
			rec.TimeKind = "event"
		}
		rec.Ident = strings.Trim(m[3], "<>")
		rec.Message = m[4]
	default:
		rec.Message = line // continuation or free-form line: kept, untyped
	}
	rec.RecordType = "syslog_line"
	if rt := families.Type(rec.Ident, rec.Message, &rec.Typed); rt != "" {
		rec.RecordType = rt
	}
}

// parseLog emits one record per line of one log stream.
func parseLog(rd io.Reader, ref time.Time, loc *time.Location, w *record.Writer) (int, error) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	emitted, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		rec := &syslogRecord{Line: lineNo}
		parseLine(line, ref, loc, rec)
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "gosyslog",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			return isSyslogFile(rel)
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		f, err := discover.OpenAuto(item)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		ref := time.Now().UTC()
		if st, err := os.Stat(item); err == nil {
			ref = st.ModTime().UTC()
		}
		return parseLog(f, ref, cfg.Knowledge().Location(), w)
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one log file")
		dir   = flag.String("d", "", "recurse a directory for syslog-family files")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gosyslog                           (env-driven batch mode)\n"+
			"       gosyslog -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		f, err := discover.OpenAuto(path)
		if err == nil {
			ref := time.Now().UTC()
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "gosyslog", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				ref = st.ModTime().UTC()
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseLog(f, ref, nil, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gosyslog: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return isSyslogFile(rel) })
		if err != nil {
			fmt.Fprintf(os.Stderr, "gosyslog: %v\n", err)
			os.Exit(1)
		}
		for _, it := range items {
			rel, rerr := filepath.Rel(*dir, it)
			if rerr != nil {
				rel = it
			}
			one(it, filepath.ToSlash(rel))
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "gosyslog: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
