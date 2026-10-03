// gowtmp — Linux login-record parser for the DX_DFIR pipeline: the P0 pilot
// of the Linux matrix (docs/linux §4), built on the shared pinfo module.
//
// Parses the classic glibc binary login records:
//
//   - utmp/wtmp/btmp — 384-byte `struct utmp` records (wtmp is the history,
//     btmp the failed logins), rotations and gzip included;
//   - lastlog — the sparse per-UID last-login table (292-byte records, the
//     UID is the record index).
//
// Records follow the byakugan-alignment rules (docs/linux §4.1): the utmp
// record type stays the native 1–9 vocabulary (never CAR's login_type), a
// field the artefact does not carry is omitted, and the l2t_utmp field floor
// (Username, Hostname, IPAddress, PID, Terminal, TerminalID, ExitStatus,
// LoginType) is carried in full. Relationships and canonicalisation are
// byakugan's; identity fields (PID + Terminal + EventTime) are carried,
// never minted (the rules).
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch): it reads GOWTMP_INPUT_DIR / GOWTMP_OUT_DIR / GOWTMP_FORCE,
// finds every utmp-family file under the input tree, writes
// one output folder per file and prints one JSON summary line. The argv
// flags below are the debug pass-through:
//
//	gowtmp -f FILE | -d DIR | --tar [-q]
//
// argv exit codes: 0 = every file parsed; 1 = usage or fatal error; 2 = at
// least one file failed to parse. Batch mode uses the uniform 0/1/2/3 table.
package wtmp

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Get-Sybers/gopinfo/batch"
	"github.com/Get-Sybers/gopinfo/discover"
	"github.com/Get-Sybers/gopinfo/knowledge"
	"github.com/Get-Sybers/gopinfo/record"
	"github.com/Get-Sybers/gopinfo/tarstream"
	"github.com/Get-Sybers/gopinfo/tstamp"
)

// utmp record types (utmp(5)); the native vocabulary is emitted verbatim.
const (
	utEmpty      = 0
	utAccounting = 9
	utmpRecLen   = 384
	lastlogLen   = 292
	// macOS utmpx on disk (private/var/run/utmpx, var/log/wtmp on older
	// releases): 628-byte records — ut_user[256], ut_id[4], ut_line[32],
	// ut_pid, ut_type, then a 32-bit timeval at 300, ut_host[256] at 308
	utmpxRecLen  = 628
	utmpxSigType = 10 // SIGNATURE: the "utmpx-1.00" head record
)

var utTypeNames = map[int16]string{
	0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
	5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS",
	9: "ACCOUNTING",
}

// utmpxTypeNames is the macOS vocabulary (utmpx.h): OLD/NEW_TIME swap
// places against glibc, and SIGNATURE / SHUTDOWN_TIME are added.
var utmpxTypeNames = map[int16]string{
	0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "OLD_TIME", 4: "NEW_TIME",
	5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS",
	9: "ACCOUNTING", 10: "SIGNATURE", 11: "SHUTDOWN_TIME",
}

// utmpRecord is one struct-utmp entry (RecordType "utmp"); Source says which
// file family it came from (utmp, wtmp, btmp — btmp rows are failed logins).
type utmpRecord struct {
	record.Envelope
	Source        string `json:"Source"`
	LoginType     int16  `json:"LoginType"`
	LoginTypeName string `json:"LoginTypeName,omitempty"`
	PID           int32  `json:"PID,omitempty"`
	Terminal      string `json:"Terminal,omitempty"`
	TerminalID    string `json:"TerminalID,omitempty"`
	Username      string `json:"Username,omitempty"`
	Hostname      string `json:"Hostname,omitempty"`
	IPAddress     string `json:"IPAddress,omitempty"`
	ExitTerm      int16  `json:"ExitTermination,omitempty"`
	ExitStatus    int16  `json:"ExitStatus,omitempty"`
	Session       int32  `json:"Session,omitempty"`
}

// lastlogRecord is one populated lastlog slot (RecordType "lastlog").
type lastlogRecord struct {
	record.Envelope
	Source   string `json:"Source"`
	UID      uint32 `json:"UID"`
	UIDName  string `json:"UIDName,omitempty"`
	Terminal string `json:"Terminal,omitempty"`
	Hostname string `json:"Hostname,omitempty"`
}

// ---- discovery -------------------------------------------------------------

// utmpBases are the file families parsed as struct-utmp records; lastlogBase
// as the lastlog table. Rotations (".1", "-20260901", ".gz") count.
var utmpBases = []string{"utmpx", "wtmp", "utmp", "btmp"}

const lastlogBase = "lastlog"

// classify returns the family ("wtmp"/"utmp"/"btmp"/"lastlog") of a file
// base name, or "" when the file is not gowtmp's.
func classify(base string) string {
	for _, b := range utmpBases {
		if discover.Rotated(base, b) {
			return b
		}
	}
	if discover.Rotated(base, lastlogBase) {
		return lastlogBase
	}
	return ""
}

// ---- parsing ---------------------------------------------------------------

// cstr trims a fixed C string field at its first NUL.
func cstr(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// addr renders ut_addr_v6: IPv4 when only the first word is set, IPv6
// otherwise, "" when unset.
func addr(b []byte) string {
	allZero := func(p []byte) bool {
		for _, x := range p {
			if x != 0 {
				return false
			}
		}
		return true
	}
	if allZero(b) {
		return ""
	}
	if allZero(b[4:16]) {
		return net.IP(b[0:4]).String()
	}
	return net.IP(b[0:16]).String()
}

// parseUtmp reads 384-byte struct-utmp records from r, emitting one record
// per non-EMPTY entry. It tolerates a truncated trailing record (warned, not
// fatal) but rejects a stream whose records do not look like glibc utmp.
func parseUtmp(r io.Reader, source string, w *record.Writer, warnf func(string, ...interface{})) (int, error) {
	buf := make([]byte, utmpRecLen)
	emitted, valid, invalid := 0, 0, 0
	for {
		_, err := io.ReadFull(r, buf)
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			if valid > 0 {
				warnf("truncated trailing record ignored")
				break
			}
			return emitted, fmt.Errorf("short file: not utmp records")
		}
		if err != nil {
			return emitted, err
		}
		ut := int16(binary.LittleEndian.Uint16(buf[0:2]))
		if ut < utEmpty || ut > utAccounting {
			invalid++
			if invalid > valid+8 {
				return emitted, fmt.Errorf("not a glibc utmp layout (record type %d)", ut)
			}
			continue
		}
		valid++
		if ut == utEmpty {
			continue
		}
		rec := &utmpRecord{
			Source:        source,
			LoginType:     ut,
			LoginTypeName: utTypeNames[ut],
			PID:           int32(binary.LittleEndian.Uint32(buf[4:8])),
			Terminal:      cstr(buf[8:40]),
			TerminalID:    cstr(buf[40:44]),
			Username:      cstr(buf[44:76]),
			Hostname:      cstr(buf[76:332]),
			ExitTerm:      int16(binary.LittleEndian.Uint16(buf[332:334])),
			ExitStatus:    int16(binary.LittleEndian.Uint16(buf[334:336])),
			Session:       int32(binary.LittleEndian.Uint32(buf[336:340])),
			IPAddress:     addr(buf[348:364]),
		}
		sec := int64(int32(binary.LittleEndian.Uint32(buf[340:344])))
		usec := int64(int32(binary.LittleEndian.Uint32(buf[344:348])))
		rec.RecordType = "utmp"
		rec.EventTime = tstamp.Unix(sec, usec*1000)
		rec.TimeKind = "event"
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	if valid == 0 && emitted == 0 {
		return 0, fmt.Errorf("no utmp records found")
	}
	if invalid > 0 {
		warnf("%d records with out-of-range type skipped", invalid)
	}
	return emitted, nil
}

// parseLastlog reads the sparse per-UID table, emitting one record per
// populated slot (zero-time, empty slots are the table's normal state).
func parseLastlog(r io.Reader, ks *knowledge.Store, w *record.Writer, warnf func(string, ...interface{})) (int, error) {
	buf := make([]byte, lastlogLen)
	emitted := 0
	var uid uint32
	for ; ; uid++ {
		_, err := io.ReadFull(r, buf)
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			warnf("truncated trailing lastlog slot ignored")
			break
		}
		if err != nil {
			return emitted, err
		}
		sec := int64(int32(binary.LittleEndian.Uint32(buf[0:4])))
		line, host := cstr(buf[4:36]), cstr(buf[36:292])
		if sec == 0 && line == "" && host == "" {
			continue
		}
		rec := &lastlogRecord{Source: lastlogBase, UID: uid, Terminal: line, Hostname: host}
		rec.UIDName = ks.Username(strconv.FormatUint(uint64(uid), 10))
		rec.RecordType = "lastlog"
		rec.EventTime = tstamp.Unix(sec, 0)
		rec.TimeKind = "last_login"
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, nil
}

// parseUtmpx reads macOS 628-byte utmpx records. The file opens with a
// SIGNATURE record ("utmpx-1.00"), which is not a login and is skipped.
func parseUtmpx(r io.Reader, source string, w *record.Writer, warnf func(string, ...interface{})) (int, error) {
	buf := make([]byte, utmpxRecLen)
	emitted, valid, invalid := 0, 0, 0
	for {
		_, err := io.ReadFull(r, buf)
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			if valid > 0 {
				warnf("truncated trailing record ignored")
				break
			}
			return emitted, fmt.Errorf("short file: not utmpx records")
		}
		if err != nil {
			return emitted, err
		}
		ut := int16(binary.LittleEndian.Uint16(buf[296:298]))
		if ut < 0 || ut > 11 {
			invalid++
			if invalid > valid+8 {
				return emitted, fmt.Errorf("not a macOS utmpx layout (record type %d)", ut)
			}
			continue
		}
		valid++
		if ut == utEmpty || ut == utmpxSigType {
			continue
		}
		rec := &utmpRecord{
			Source:        source,
			LoginType:     ut,
			LoginTypeName: utmpxTypeNames[ut],
			Username:      cstr(buf[0:256]),
			TerminalID:    cstr(buf[256:260]),
			Terminal:      cstr(buf[260:292]),
			PID:           int32(binary.LittleEndian.Uint32(buf[292:296])),
			Hostname:      cstr(buf[308:564]),
		}
		sec := int64(int32(binary.LittleEndian.Uint32(buf[300:304])))
		usec := int64(int32(binary.LittleEndian.Uint32(buf[304:308])))
		rec.RecordType = "utmp"
		rec.EventTime = tstamp.Unix(sec, usec*1000)
		rec.TimeKind = "event"
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	if valid == 0 && emitted == 0 {
		return 0, fmt.Errorf("no utmpx records found")
	}
	if invalid > 0 {
		warnf("%d records with out-of-range type skipped", invalid)
	}
	return emitted, nil
}

// parseStream dispatches one input by family.
func parseStream(r io.Reader, family string, ks *knowledge.Store, w *record.Writer, warnf func(string, ...interface{})) (int, error) {
	switch family {
	case lastlogBase:
		return parseLastlog(r, ks, w, warnf)
	case "utmpx":
		return parseUtmpx(r, family, w, warnf)
	}
	return parseUtmp(r, family, w, warnf)
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "gowtmp",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			return classify(strings.ToLower(filepath.Base(rel))) != ""
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		family := classify(strings.ToLower(filepath.Base(item)))
		f, err := discover.OpenAuto(item)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return parseStream(f, family, cfg.Knowledge(), w, func(format string, args ...interface{}) {
			cfg.Logf(batch.LogWarn, item+": "+format, args...)
		})
	},
}

// ---- argv mode (debug pass-through) ----------------------------------------

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one utmp/wtmp/btmp/lastlog file")
		dir   = flag.String("d", "", "recurse a directory for utmp-family files")
		tarIn = flag.Bool("tar", false, "read a tar stream on stdin (gomount stream)")
		quiet = flag.Bool("q", false, "suppress per-file progress on stderr")
	)
	flag.Parse()
	modes := 0
	for _, on := range []bool{*file != "", *dir != "", *tarIn} {
		if on {
			modes++
		}
	}
	if modes != 1 || flag.NArg() != 0 {
		usage()
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	warnf := func(format string, args ...interface{}) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "gowtmp: "+format+"\n", args...)
		}
	}
	failed := 0
	one := func(path, rel string) {
		family := classify(strings.ToLower(filepath.Base(path)))
		if family == "" {
			warnf("%s: not a utmp-family name, skipped", path)
			return
		}
		f, err := discover.OpenAuto(path)
		if err != nil {
			warnf("%s: %v", path, err)
			failed++
			return
		}
		defer f.Close()
		st, _ := os.Stat(path)
		s := record.Stamp{Tool: "gowtmp", ToolVersion: version, SourceFilename: rel}
		if st != nil {
			s.SourceModified = tstamp.ISO8601(st.ModTime())
		}
		w.SetStamp(s)
		if _, err := parseStream(f, family, nil, w, warnf); err != nil {
			warnf("%s: %v", path, err)
			failed++
		}
	}
	switch {
	case *file != "":
		one(*file, *file)
	case *dir != "":
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool {
			return classify(strings.ToLower(filepath.Base(rel))) != ""
		})
		if err != nil {
			fatal(err)
		}
		for _, it := range items {
			rel, rerr := filepath.Rel(*dir, it)
			if rerr != nil {
				rel = it
			}
			one(it, filepath.ToSlash(rel))
		}
	case *tarIn:
		err := tarstream.Each(os.Stdin, func(e tarstream.Entry) error {
			family := classify(strings.ToLower(filepath.Base(e.Name)))
			if family == "" {
				return nil
			}
			w.SetStamp(record.Stamp{
				Tool: "gowtmp", ToolVersion: version,
				SourceFilename: e.Name, SourceModified: tstamp.ISO8601(e.Mod),
			})
			if _, perr := parseStream(e.R, family, nil, w, warnf); perr != nil {
				warnf("%s: %v", e.Name, perr)
				failed++
			}
			return nil
		})
		if err != nil {
			fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		fatal(err)
	}
	if failed > 0 {
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gowtmp                                  (env-driven batch mode)\n"+
		"       gowtmp -f FILE | -d DIR | --tar [-q]")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gowtmp: %v\n", err)
	os.Exit(1)
}
