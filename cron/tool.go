// gocron — Linux scheduled-task parser for the DX_DFIR pipeline
// (docs/linux §4): the Scheduled Tasks surface. Finds system and user
// crontabs, cron.d fragments, run-parts directories, anacrontab and at
// spool jobs under the input tree and emits typed records.
//
// Rules (docs/linux §4.1): schedules are recorded verbatim (the five-field
// or @keyword spec), the user column only where the format carries one (a
// spool crontab's owner is its filename — recorded as SpoolOwner, a fact of
// the artefact's location, never an inference beyond it). Nothing is
// resolved to next-run times; that is derivation.
//
// With no arguments the binary runs the container-framework batch mode
// (pinfo/batch) under the GOCRON_* environment. The argv flags are the
// debug pass-through:
//
//	gocron -f FILE | -d DIR [-q]
package cron

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/get-sybers/gopinfo/batch"
	"github.com/get-sybers/gopinfo/discover"
	"github.com/get-sybers/gopinfo/record"
	"github.com/get-sybers/gopinfo/tstamp"
)

// cronRecord is the one record shape; RecordType distinguishes
// crontab_entry, crontab_env, anacrontab_entry and at_job rows.
type cronRecord struct {
	record.Envelope
	Schedule   string `json:"Schedule,omitempty"`
	User       string `json:"User,omitempty"`
	SpoolOwner string `json:"SpoolOwner,omitempty"`
	Command    string `json:"Command,omitempty"`
	Name       string `json:"Name,omitempty"`
	Value      string `json:"Value,omitempty"`
	Period     string `json:"Period,omitempty"`
	Delay      string `json:"Delay,omitempty"`
	JobID      string `json:"JobID,omitempty"`
	AtUID      string `json:"AtUID,omitempty"`
	AtGID      string `json:"AtGID,omitempty"`
	Script     string `json:"Script,omitempty"`
	Line       int    `json:"Line"`
	Raw        string `json:"Raw,omitempty"`
}

// ---- classification --------------------------------------------------------

// family returns the parse family of a rel path, "" when not gocron's:
// "system" (crontab / cron.d — a user column), "spool" (user crontabs — no
// user column, owner = filename), "anacron", "at".
func family(rel string) (fam, spoolOwner string) {
	rel = strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(rel)
	dir := filepath.Dir(rel)
	dirBase := filepath.Base(dir)
	switch {
	case base == "crontab":
		return "system", ""
	case base == "anacrontab":
		return "anacron", ""
	case dirBase == "cron.d":
		return "system", ""
	case dirBase == "cron.hourly" || dirBase == "cron.daily" ||
		dirBase == "cron.weekly" || dirBase == "cron.monthly":
		return "runparts", ""
	case strings.HasSuffix(dir, "var/spool/cron/crontabs") || dirBase == "crontabs" && strings.Contains(dir, "spool"):
		return "spool", base
	case strings.HasSuffix(dir, "var/spool/cron") && base != "atjobs" && base != "atspool":
		return "spool", base
	case strings.Contains(dir, "spool/at") || dirBase == "atjobs":
		if strings.HasPrefix(base, "a") && len(base) >= 8 {
			return "at", ""
		}
	// macOS: user crontabs under var/at/tabs (owner = filename), at jobs
	// under var/at/jobs, the periodic run-parts under etc/periodic/<when>
	// and their configuration
	case strings.HasSuffix(dir, "var/at/tabs"):
		return "spool", base
	case strings.HasSuffix(dir, "var/at/jobs"):
		if strings.HasPrefix(base, "a") && len(base) >= 8 {
			return "at", ""
		}
	case (dirBase == "daily" || dirBase == "weekly" || dirBase == "monthly") && filepath.Base(filepath.Dir(dir)) == "periodic":
		return "runparts", ""
	case base == "periodic.conf" || base == "periodic.conf.local":
		return "conf", ""
	}
	return "", ""
}

var scheduleRe = regexp.MustCompile(`^(@[a-z]+|(?:[-0-9*/,a-zA-Z]+\s+){4}[-0-9*/,a-zA-Z]+)\s+(.*)$`)
var envRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)

// parseCrontab parses crontab-format content; withUser says whether lines
// carry the user column (system crontab and cron.d do, spool files do not).
func parseCrontab(rd io.Reader, withUser bool, spoolOwner string, w *record.Writer) (int, error) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	emitted, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rec := &cronRecord{Line: lineNo, SpoolOwner: spoolOwner}
		if m := envRe.FindStringSubmatch(line); m != nil && !strings.HasPrefix(line, "@") {
			rec.RecordType = "crontab_env"
			rec.Name, rec.Value = m[1], m[2]
		} else if m := scheduleRe.FindStringSubmatch(line); m != nil {
			rec.RecordType = "crontab_entry"
			rec.Schedule = strings.Join(strings.Fields(m[1]), " ")
			rest := m[2]
			if withUser {
				f := strings.Fields(rest)
				if len(f) >= 2 {
					rec.User = f[0]
					rec.Command = strings.TrimSpace(strings.TrimPrefix(rest, f[0]))
				} else {
					rec.Command = rest
				}
			} else {
				rec.Command = rest
			}
		} else {
			rec.RecordType = "crontab_entry"
			rec.Raw = line
		}
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

// parseAnacrontab: period delay job-identifier command (env lines too).
func parseAnacrontab(rd io.Reader, w *record.Writer) (int, error) {
	sc := bufio.NewScanner(rd)
	emitted, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rec := &cronRecord{Line: lineNo}
		if m := envRe.FindStringSubmatch(line); m != nil {
			rec.RecordType = "crontab_env"
			rec.Name, rec.Value = m[1], m[2]
		} else {
			f := strings.Fields(line)
			rec.RecordType = "anacrontab_entry"
			if len(f) >= 4 {
				rec.Period, rec.Delay, rec.JobID = f[0], f[1], f[2]
				rec.Command = strings.Join(f[3:], " ")
			} else {
				rec.Raw = line
			}
		}
		if err := w.Write(rec); err != nil {
			return emitted, err
		}
		emitted++
	}
	return emitted, sc.Err()
}

var atMetaRe = regexp.MustCompile(`(?m)^# atrun uid=(\d+) gid=(\d+)`)

// parseAtJob records one at spool job: the queue file name is the JobID,
// the "# atrun uid= gid=" header names the owner when present, and the
// script tail (past the environment restore block) is captured up to 64 KiB.
func parseAtJob(rd io.Reader, jobFile string, w *record.Writer) (int, error) {
	const maxScript = 64 * 1024
	b, err := io.ReadAll(io.LimitReader(rd, maxScript+1))
	if err != nil {
		return 0, err
	}
	truncated := false
	if len(b) > maxScript {
		b, truncated = b[:maxScript], true
	}
	rec := &cronRecord{Line: 1}
	rec.RecordType = "at_job"
	rec.JobID = jobFile
	body := string(b)
	if m := atMetaRe.FindStringSubmatch(body); m != nil {
		rec.AtUID, rec.AtGID = m[1], m[2]
	}
	rec.Script = body
	if truncated {
		rec.Script += "\n# [gocron: script truncated at 64KiB]"
	}
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

// parseRunParts records one script's membership of a cron.{hourly,daily,
// weekly,monthly} run-parts directory; the script body is not parsed.
func parseRunParts(rel string, w *record.Writer) (int, error) {
	rec := &cronRecord{Line: 1}
	rec.RecordType = "cron_runparts"
	rec.Name = filepath.Base(rel)
	rec.Value = filepath.Base(filepath.Dir(rel))
	if err := w.Write(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

func parseByFamily(rd io.Reader, fam, spoolOwner, base, rel string, w *record.Writer) (int, error) {
	switch fam {
	case "system":
		return parseCrontab(rd, true, "", w)
	case "spool":
		return parseCrontab(rd, false, spoolOwner, w)
	case "anacron":
		return parseAnacrontab(rd, w)
	case "at":
		return parseAtJob(rd, base, w)
	case "runparts":
		return parseRunParts(rel, w)
	case "conf":
		return parseCrontab(rd, false, "", w) // KEY=value rows come out as crontab_env
	}
	return 0, fmt.Errorf("unknown family %q", fam)
}

// ---- batch binding ---------------------------------------------------------

var Tool = batch.Tool{
	Name: "gocron",
	Discover: func(cfg *batch.Config) ([]string, error) {
		return discover.Files(cfg.InputDir, func(rel string, d fs.DirEntry) bool {
			f, _ := family(rel)
			return f != ""
		})
	},
	Process: func(cfg *batch.Config, item, _ string, w *record.Writer) (int, error) {
		rel, _ := filepath.Rel(cfg.InputDir, item)
		fam, owner := family(filepath.ToSlash(rel))
		f, err := os.Open(item)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return parseByFamily(f, fam, owner, filepath.Base(item), filepath.ToSlash(rel), w)
	},
}

// Main is the standalone binary entry: the framework Entry (batch mode,
// --version/--print-contract) then the argv debug pass-through.
func Main(version, contractYML string) {
	batch.Entry(Tool, batch.Options{Version: version, Contract: contractYML})

	var (
		file  = flag.String("f", "", "parse one crontab/anacrontab/at file")
		dir   = flag.String("d", "", "recurse a directory")
		quiet = flag.Bool("q", false, "suppress warnings on stderr")
	)
	flag.Parse()
	if (*file == "") == (*dir == "") || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gocron                             (env-driven batch mode)\n"+
			"       gocron -f FILE | -d DIR [-q]")
		os.Exit(1)
	}
	w := record.NewWriter(os.Stdout)
	failed := 0
	one := func(path, rel string) {
		fam, owner := family(rel)
		if fam == "" {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gocron: %s: not a gocron file, skipped\n", path)
			}
			return
		}
		f, err := os.Open(path)
		if err == nil {
			st, _ := os.Stat(path)
			s := record.Stamp{Tool: "gocron", ToolVersion: version, SourceFilename: rel}
			if st != nil {
				s.SourceModified = tstamp.ISO8601(st.ModTime())
			}
			w.SetStamp(s)
			_, err = parseByFamily(f, fam, owner, filepath.Base(path), rel, w)
			f.Close()
		}
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "gocron: %s: %v\n", path, err)
			}
			failed++
		}
	}
	if *file != "" {
		one(*file, *file)
	} else {
		items, err := discover.Files(*dir, func(rel string, d fs.DirEntry) bool {
			f, _ := family(rel)
			return f != ""
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "gocron: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "gocron: %v\n", err)
		os.Exit(1)
	}
	if failed > 0 {
		os.Exit(2)
	}
}
