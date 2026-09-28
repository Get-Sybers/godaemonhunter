// gojournal — systemd journal parser for the DX_DFIR pipeline
// (docs/linux §4): the Linux evtx. Finds every binary journal file under
// the input tree — `*.journal` and dirty `*.journal~` alike, system and
// per-user — and emits one record per entry, streaming: no journal is ever
// held in memory whole. Compressed data payloads (XZ, LZ4, ZSTD by object
// flag) decode with pure-Go readers; compact-mode files (systemd 252+) are
// supported.
//
// Rules (docs/linux §4.1): fields are the journal's own, verbatim — the
// well-known set is lifted to named columns (MESSAGE, PRIORITY, _PID,
// _UID, _COMM, _EXE, _CMDLINE, _SYSTEMD_UNIT, SYSLOG_IDENTIFIER,
// _HOSTNAME, …), everything else rides in a Fields map; a non-UTF-8 value
// is hex-prefixed rather than mangled. (MachineID, BootID, Seqnum) is the
// record's identity, carried never minted. `__REALTIME` microseconds land
// in EventTime.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOJOURNAL_* environment. The argv flags are the
// debug pass-through:
//
//	gojournal -f FILE | -d DIR [-q]
package journal

import (
	"bytes"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/get-sybers/gopinfo/batch"
	"github.com/get-sybers/gopinfo/discover"
	"github.com/get-sybers/gopinfo/families"
	"github.com/get-sybers/gopinfo/knowledge"
	"github.com/get-sybers/gopinfo/record"
	"github.com/get-sybers/gopinfo/tstamp"
)

// journalRecord is one journal entry (RecordType "journal_entry").
type journalRecord struct {
	record.Envelope
	MachineID    string `json:"MachineID,omitempty"`
	BootID       string `json:"BootID,omitempty"`
	Seqnum       uint64 `json:"Seqnum"`
	MonotonicUS  uint64 `json:"MonotonicUS,omitempty"`
	Message      string `json:"Message,omitempty"`
	Priority     string `json:"Priority,omitempty"`
	Facility     string `json:"Facility,omitempty"`
	Identifier   string `json:"Identifier,omitempty"`
	PID          string `json:"PID,omitempty"`
	UID          string `json:"UID,omitempty"`
	UIDName      string `json:"UIDName,omitempty"`
	GID          string `json:"GID,omitempty"`
	GIDName      string `json:"GIDName,omitempty"`
	Comm         string `json:"Comm,omitempty"`
	Exe          string `json:"Exe,omitempty"`
	Cmdline      string `json:"Cmdline,omitempty"`
	SystemdUnit  string `json:"SystemdUnit,omitempty"`
	UserUnit     string `json:"UserUnit,omitempty"`
	Hostname     string `json:"Hostname,omitempty"`
	Transport    string `json:"Transport,omitempty"`
	AuditSession string `json:"AuditSession,omitempty"`
	// the typed families (sshd, sudo, pam, cron), recognised by the shared
	// pinfo/families engine: on a systemd host the journal is the PRIMARY
	// pathway for these events — sshd and friends log through it, and the
	// flat auth.log may not exist at all — so a matching entry carries the
	// family RecordType and fields in addition to every journal field.
	families.Typed
	Fields    map[string]string `json:"Fields,omitempty"`
	Truncated bool              `json:"Truncated,omitempty"`
}

const maxExtraFields = 128

// lifted maps a journal field name to the record column it fills.
var lifted = map[string]func(*journalRecord, string){
	"MESSAGE":            func(r *journalRecord, v string) { r.Message = v },
	"PRIORITY":           func(r *journalRecord, v string) { r.Priority = v },
	"SYSLOG_FACILITY":    func(r *journalRecord, v string) { r.Facility = v },
	"SYSLOG_IDENTIFIER":  func(r *journalRecord, v string) { r.Identifier = v },
	"_PID":               func(r *journalRecord, v string) { r.PID = v },
	"_UID":               func(r *journalRecord, v string) { r.UID = v },
	"_GID":               func(r *journalRecord, v string) { r.GID = v },
	"_COMM":              func(r *journalRecord, v string) { r.Comm = v },
	"_EXE":               func(r *journalRecord, v string) { r.Exe = v },
	"_CMDLINE":           func(r *journalRecord, v string) { r.Cmdline = v },
	"_SYSTEMD_UNIT":      func(r *journalRecord, v string) { r.SystemdUnit = v },
	"_SYSTEMD_USER_UNIT": func(r *journalRecord, v string) { r.UserUnit = v },
	"_HOSTNAME":          func(r *journalRecord, v string) { r.Hostname = v },
	"_TRANSPORT":         func(r *journalRecord, v string) { r.Transport = v },
	"_AUDIT_SESSION":     func(r *journalRecord, v string) { r.AuditSession = v },
}

// safeValue keeps a payload value honest: valid UTF-8 verbatim, binary
// hex-prefixed so nothing is mangled.
func safeValue(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return "hex:" + fmt.Sprintf("%x", b)
}

// buildRecord shapes one decoded entry into the output record.
func buildRecord(e *entry, machineID string, ks *knowledge.Store) *journalRecord {
	rec := &journalRecord{
		MachineID: machineID, BootID: e.bootID, Seqnum: e.seqnum,
		MonotonicUS: e.monotonic, Truncated: e.truncated,
	}
	rec.RecordType = "journal_entry"
	rec.EventTime = tstamp.UnixMicros(int64(e.realtime))
	rec.TimeKind = "event"
	for _, f := range e.fields {
		// Split on the raw bytes: the value may be binary, and safeValue
		// must see it untouched to hex it faithfully.
		kb, v, ok := bytes.Cut(f, []byte{'='})
		if !ok {
			continue
		}
		k := string(kb)
		if fill, known := lifted[k]; known {
			fill(rec, safeValue(v))
			continue
		}
		if rec.Fields == nil {
			rec.Fields = map[string]string{}
		}
		if len(rec.Fields) < maxExtraFields {
			if _, dup := rec.Fields[k]; !dup {
				rec.Fields[k] = safeValue(v)
			}
		} else {
			rec.Truncated = true
		}
	}
	ident := rec.Identifier
	if ident == "" {
		ident = rec.Comm
	}
	if rt := families.Type(ident, rec.Message, &rec.Typed); rt != "" {
		rec.RecordType = rt
	}
	rec.UIDName = ks.Username(rec.UID)
	rec.GIDName = ks.Groupname(rec.GID)
	return rec
}

// parseJournal streams one journal file's entries into the writer.
func parseJournal(path string, ks *knowledge.Store, w *record.Writer, warnf func(string, ...interface{})) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	j, err := openJournal(f, st.Size())
	if err != nil {
		return 0, err
	}
	defer j.close()

	emitted, unreadable := 0, 0
	err = j.entryOffsets(func(off uint64) error {
		e, rerr := j.readEntry(off)
		if rerr != nil {
			unreadable++
			return nil // dirty tail: keep going, count it
		}
		if werr := w.Write(buildRecord(e, j.hdr.machineID, ks)); werr != nil {
			return werr
		}
		emitted++
		return nil
	})
	if err != nil && emitted == 0 {
		return emitted, err
	}
	if err != nil {
		warnf("entry walk stopped early: %v", err)
	}
	if unreadable > 0 {
		warnf("%d unreadable entries skipped (dirty or truncated journal)", unreadable)
	}
	return emitted, nil
}

func isJournalFile(rel string) bool {
	base := strings.ToLower(filepath.Base(rel))
	return strings.HasSuffix(base, ".journal") || strings.HasSuffix(base, ".journal~")
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "gojournal",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			return isJournalFile(rel)
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		return parseJournal(item, cfg.Knowledge(), w, func(format string, args ...interface{}) {
			cfg.Logf(batch.LogWarn, item+": "+format, args...)
		})
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one .journal file")
		dir   = flag.String("d", "", "recurse a directory for journal files")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gojournal                          (env-driven batch mode)\n"+
			"       gojournal -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	warnf := func(f string, a ...interface{}) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "gojournal: "+f+"\n", a...)
		}
	}
	failed := 0
	one := func(path, rel string) {
		st, _ := os.Stat(path)
		s := record.Stamp{Tool: "gojournal", ToolVersion: version, SourceFilename: rel}
		if st != nil {
			s.SourceModified = tstamp.ISO8601(st.ModTime())
		}
		w.SetStamp(s)
		if _, err := parseJournal(path, nil, w, warnf); err != nil {
			warnf("%s: %v", path, err)
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return isJournalFile(rel) })
		if err != nil {
			fmt.Fprintf(os.Stderr, "gojournal: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "gojournal: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
