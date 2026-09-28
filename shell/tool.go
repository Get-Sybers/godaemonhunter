// goshell — shell and REPL history parser for the DX_DFIR pipeline
// (docs/linux §4). Finds per-user history files under the input tree —
// .bash_history, .zsh_history (extended format, metafied bytes decoded),
// fish_history, .sh_history, .python_history, .mysql_history,
// .psql_history — and emits one record per command, sequence order
// preserved.
//
// Rules (docs/linux §4.1): EventTime is set only when the artefact really
// carries a time (zsh extended stamps, bash HISTTIMEFORMAT `#<epoch>`
// lines, fish `when:`) — never invented. The owning account is not derived
// from the path (byakugan's fill-only-null inference over SourceFilename).
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOSHELL_* environment. The argv flags are the
// debug pass-through:
//
//	goshell -f FILE | -d DIR [-q]
package shell

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

	"github.com/get-sybers/gopinfo/batch"
	"github.com/get-sybers/gopinfo/discover"
	"github.com/get-sybers/gopinfo/record"
	"github.com/get-sybers/gopinfo/tstamp"
)

// historyRecord is one command (RecordType "shell_history").
type historyRecord struct {
	record.Envelope
	Shell    string `json:"Shell"`
	Sequence int    `json:"Sequence"`
	Command  string `json:"Command"`
	Elapsed  *int64 `json:"Elapsed,omitempty"` // zsh extended: seconds the command ran
}

// shells maps recognised base names to the shell family.
var shells = map[string]string{
	".bash_history":   "bash",
	"bash_history":    "bash",
	".zsh_history":    "zsh",
	"zsh_history":     "zsh",
	".sh_history":     "sh",
	"sh_history":      "sh",
	".python_history": "python",
	".mysql_history":  "mysql",
	".psql_history":   "psql",
	"fish_history":    "fish",
	".ash_history":    "sh",
}

func classify(rel string) string {
	base := strings.ToLower(filepath.Base(rel))
	if s := shells[base]; s != "" {
		return s
	}
	// macOS Terminal keeps one history per session: .bash_sessions/<id>.history
	// (and .historynew while a session is open), .zsh_sessions/<id>.history
	if strings.HasSuffix(base, ".history") || strings.HasSuffix(base, ".historynew") {
		switch strings.ToLower(filepath.Base(filepath.Dir(rel))) {
		case ".bash_sessions":
			return "bash"
		case ".zsh_sessions":
			return "zsh"
		}
	}
	return ""
}

// zshUnmetafy reverses zsh's metafication: 0x83 marks the next byte XOR 0x20.
func zshUnmetafy(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == 0x83 && i+1 < len(b) {
			i++
			out = append(out, b[i]^0x20)
		} else {
			out = append(out, b[i])
		}
	}
	return out
}

var (
	zshExtRe    = regexp.MustCompile(`^: (\d+):(\d+);(.*)$`)
	bashStampRe = regexp.MustCompile(`^#(\d{9,10})$`)
	fishCmdRe   = regexp.MustCompile(`^- cmd:\s?(.*)$`)
	fishWhenRe  = regexp.MustCompile(`^\s+when:\s?(\d+)$`)
)

// parseHistory emits one record per command for the given shell family.
func parseHistory(rd io.Reader, shell string, w *record.Writer) (int, error) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	emitted, seq := 0, 0
	pendingStamp := "" // bash: a #<epoch> line stamps the NEXT command
	var fishRec *historyRecord

	flushFish := func() error {
		if fishRec == nil {
			return nil
		}
		if err := w.Write(fishRec); err != nil {
			return err
		}
		emitted++
		fishRec = nil
		return nil
	}

	emit := func(cmd, when string, elapsed *int64) error {
		seq++
		rec := &historyRecord{Shell: shell, Sequence: seq, Command: cmd, Elapsed: elapsed}
		rec.RecordType = "shell_history"
		if when != "" {
			if n, err := strconv.ParseInt(when, 10, 64); err == nil {
				rec.EventTime = tstamp.Unix(n, 0)
				rec.TimeKind = "command"
			}
		}
		if err := w.Write(rec); err != nil {
			return err
		}
		emitted++
		return nil
	}

	for sc.Scan() {
		raw := sc.Bytes()
		if shell == "zsh" {
			raw = zshUnmetafy(raw)
		}
		line := strings.TrimRight(string(raw), "\r")
		switch shell {
		case "fish":
			if m := fishCmdRe.FindStringSubmatch(line); m != nil {
				if err := flushFish(); err != nil {
					return emitted, err
				}
				seq++
				fishRec = &historyRecord{Shell: shell, Sequence: seq, Command: m[1]}
				fishRec.RecordType = "shell_history"
			} else if m := fishWhenRe.FindStringSubmatch(line); m != nil && fishRec != nil {
				if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
					fishRec.EventTime = tstamp.Unix(n, 0)
					fishRec.TimeKind = "command"
				}
			}
			// other yaml keys (paths:) are skipped
		case "zsh":
			if m := zshExtRe.FindStringSubmatch(line); m != nil {
				var el *int64
				if n, err := strconv.ParseInt(m[2], 10, 64); err == nil {
					el = &n
				}
				if err := emit(m[3], m[1], el); err != nil {
					return emitted, err
				}
				continue
			}
			if line == "" {
				continue
			}
			if err := emit(line, "", nil); err != nil { // plain-format zsh history
				return emitted, err
			}
		default: // bash, sh, python, mysql, psql
			if m := bashStampRe.FindStringSubmatch(line); m != nil && shell == "bash" {
				pendingStamp = m[1]
				continue
			}
			if line == "" {
				continue
			}
			if err := emit(line, pendingStamp, nil); err != nil {
				return emitted, err
			}
			pendingStamp = ""
		}
	}
	if err := flushFish(); err != nil {
		return emitted, err
	}
	return emitted, sc.Err()
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "goshell",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			return classify(rel) != ""
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		f, err := os.Open(item)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return parseHistory(f, classify(item), w)
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one history file")
		dir   = flag.String("d", "", "recurse a directory for history files")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: goshell                            (env-driven batch mode)\n"+
			"       goshell -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		shell := classify(path)
		if shell == "" {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "goshell: %s: not a history file, skipped\n", path)
			}
			return
		}
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "goshell", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseHistory(f, shell, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "goshell: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool { return classify(rel) != "" })
		if err != nil {
			fmt.Fprintf(os.Stderr, "goshell: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "goshell: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
