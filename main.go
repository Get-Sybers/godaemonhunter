// godaemonhunter — the Linux and macOS daemon matrix as ONE structured
// binary (docs/linux §4, decisions 15–17): every daemon parser lives here
// as a package and runs inside the layered one-shot — Layer 1 (gohost,
// gousers, gonetwork, and for a Mac gomachost, gomacusers) runs first and
// builds the image's knowledge store, then the daemon parsers run
// enriched by it. One binary, one run, one structured output tree, one
// JSON summary line. A Mac is the same run: its Layer-1 parsers emit the
// same record types from the property lists that carry them, golaunchd
// feeds the service stream beside gounit, and gosyslog, gowtmp, gocron,
// goshell and gousers read the macOS shapes of their artefacts.
//
// The parameter is the STREAM (decision 17): a byakugan model word that
// scopes the run to the daemon parsers feeding that model. The default
// is every stream.
//
//	godaemonhunter                     every stream — the default layered
//	                                   run, GODAEMONHUNTER_* driven
//	godaemonhunter <stream>...         scope it: authentication,
//	                                   user_session, process, service,
//	                                   flow, file, module
//	godaemonhunter <subtool>           one parser's env-driven batch mode,
//	                                   under its canonical <SUBTOOL>_* block
//	godaemonhunter <subtool> <args>    that parser's argv debug pass-through
//	                                   (-f FILE | -d DIR | --tar, -q)
//	godaemonhunter --version | --print-contract
//
// A disk image is a host too (imageitem.go): GODAEMONHUNTER_IMAGE (or a
// sub-tool's <SUBTOOL>_IMAGE) names one under the input tree — or every
// image directly under it is taken — and the parsers run ON the image: the
// baked-in gomount pulls the linux-core and macos-core artefact surfaces
// (docs/linux §5.4; whichever the OS volume holds) into the work dir, the layered run goes over that
// as over a staged root tree, the knowledge store lands per-item at
// <OUT_DIR>/knowledge/<image>/ and the Layer-2 records flat at
// <OUT_DIR>/<subtool>/<asset-id>.jsonl, the scratch goes. Nothing is exported.
// A UAC collection (the tar.gz, tar or zip UAC — github.com/tclahr/uac —
// writes) is the same item: gomount reads its [root]/ tree as
// the root volume, so IMAGE may name one and every archive under the
// input tree that `gomount identify` confirms as a collection is hunted
// beside the images.
//
// And a live system is a host too (livecollect): GODAEMONHUNTER_LIVE (or a
// sub-tool's <SUBTOOL>_LIVE) runs the parsers ON the running host. Instead of
// gomount decoding an image, livecollect copies the known artefact surface out
// of the live root (GODAEMONHUNTER_LIVE_ROOT, default /) into the work dir — so
// the walk never touches /proc, /sys or other mounts and a per-file read
// failure is skipped, not fatal — and the same layered run goes over that
// stage, the host folder named for the live host. LIVE and IMAGE are mutually
// exclusive: a run is on one source.
//
// (`hunt` stays accepted as the explicit word for the default run.) The
// multi-tool dispatcher shape of docs/framework/04 §4.3 (the plaso and
// signatures precedent). There are no standalone per-parser binaries or
// images: godaemonhunter is the Linux tool.
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Get-Sybers/gopinfo/diskimage"

	"github.com/Get-Sybers/gopinfo"
	"github.com/Get-Sybers/gopinfo/batch"
	"github.com/Get-Sybers/gopinfo/toolkit"

	"github.com/Get-Sybers/godaemonhunter/auditd"
	"github.com/Get-Sybers/godaemonhunter/cron"
	"github.com/Get-Sybers/godaemonhunter/ctl"
	"github.com/Get-Sybers/godaemonhunter/fsevents"
	"github.com/Get-Sybers/godaemonhunter/host"
	"github.com/Get-Sybers/godaemonhunter/journal"
	"github.com/Get-Sybers/godaemonhunter/launchd"
	"github.com/Get-Sybers/godaemonhunter/livecollect"
	"github.com/Get-Sybers/godaemonhunter/machost"
	"github.com/Get-Sybers/godaemonhunter/macusers"
	"github.com/Get-Sybers/godaemonhunter/network"
	"github.com/Get-Sybers/godaemonhunter/shell"
	"github.com/Get-Sybers/godaemonhunter/syslog"
	"github.com/Get-Sybers/godaemonhunter/trash"
	"github.com/Get-Sybers/godaemonhunter/unit"
	"github.com/Get-Sybers/godaemonhunter/users"
	"github.com/Get-Sybers/godaemonhunter/wtmp"
)

// argvMain is a parser package's Main: batch.Entry plus the tool's argv
// debug modes on the global flag set. It never returns on the batch,
// --version and --print-contract paths, and exits itself on argv errors.

//go:embed contract.yml
var contractYML string

// version is stamped at build time via -ldflags (-X main.version).
var version = "0.0.0-dev"

// sub is one embedded parser; layer 1 builds the knowledge store, layer 2
// consumes it. Order is the hunt execution order, deterministic.
type sub struct {
	name  string
	layer int
	tool  batch.Tool
	main  argvMain
}

type argvMain func(version, contractYML string)

var subs = []sub{
	{"gohost", 1, host.Tool, host.Main},
	{"gousers", 1, users.Tool, users.Main},
	{"gonetwork", 1, network.Tool, network.Main},
	{"gomachost", 1, machost.Tool, machost.Main},
	{"gomacusers", 1, macusers.Tool, macusers.Main},
	{"gojournal", 2, journal.Tool, journal.Main},
	{"goauditd", 2, auditd.Tool, auditd.Main},
	{"gowtmp", 2, wtmp.Tool, wtmp.Main},
	{"gosyslog", 2, syslog.Tool, syslog.Main},
	{"gounit", 2, unit.Tool, unit.Main},
	{"gocron", 2, cron.Tool, cron.Main},
	{"goshell", 2, shell.Tool, shell.Main},
	{"gotrash", 2, trash.Tool, trash.Main},
	{"goctl", 2, ctl.Tool, ctl.Main},
	{"golaunchd", 2, launchd.Tool, launchd.Main},
	{"gofsevents", 2, fsevents.Tool, fsevents.Main},
}

// streams is the calling vocabulary (decision 17): each accepted word IS a
// byakugan model (model/car/objects at the BYAKUGAN_REF pin) and selects
// the Layer-2 daemon parsers whose records feed that model's maps. Layer 1
// always runs — it is the knowledge store. The other model words (registry,
// thread, …) are not accepted until a parser here feeds them.
var streams = map[string][]string{
	"authentication": {"gojournal", "gosyslog", "gowtmp", "goauditd"},
	"user_session":   {"gowtmp", "gojournal", "gosyslog", "goauditd"},
	"process":        {"goauditd", "goshell", "gojournal", "gosyslog"},
	"service":        {"gounit", "golaunchd", "gocron", "gojournal", "gosyslog"},
	"flow":           {"goauditd"},
	"file":           {"gotrash", "gofsevents"},
	"module":         {"goctl"},
}

// imageSets is what every daemon parser reads off a disk image: the Linux
// root-filesystem surface of docs/linux §5.4 and its macOS counterpart —
// both are asked for on every image; whichever the OS volume holds is
// pulled, the other matches nothing.
var imageSets = []string{"linux-core", "macos-core"}

func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdout)) }

// run is main's testable body: no arguments is every stream (the default),
// stream words scope the hunt, a subtool name is one parser.
func run(args []string, getenv func(string) string, stdout io.Writer) int {
	if len(args) == 1 {
		switch strings.TrimLeft(args[0], "-") {
		case "version":
			fmt.Fprintf(stdout, "godaemonhunter %s\n", version)
			return 0
		case "print-contract":
			_, _ = io.WriteString(stdout, contractYML)
			return 0
		}
	}
	if len(args) == 0 || (len(args) == 1 && args[0] == "hunt") {
		return runHunt(getenv, stdout, nil)
	}
	if _, isStream := streams[args[0]]; isStream {
		for _, a := range args {
			if _, ok := streams[a]; !ok {
				fmt.Fprintf(os.Stderr, "godaemonhunter: %q is not a stream\n", a)
				usage()
				return 2
			}
		}
		return runHunt(getenv, stdout, args)
	}
	for _, s := range subs {
		if s.name != args[0] {
			continue
		}
		if len(args) == 1 {
			liveSet, lerr := batch.ParseBool(getenv(batch.Prefix(s.tool.Name) + "_LIVE"))
			if lerr != nil {
				return configErrorSummary(s.name, fmt.Errorf("%s_LIVE: %w", batch.Prefix(s.tool.Name), lerr), stdout)
			}
			if liveSet {
				return runSubOnLive(s, getenv, stdout)
			}
			if img := getenv(batch.Prefix(s.tool.Name) + "_IMAGE"); img != "" {
				return runSubOnImage(s, img, getenv, stdout)
			}
			return runSubBatch(s, getenv, stdout)
		}
		// argv debug pass-through: hand the rest of the command line to
		// the parser's own Main, busybox-style. It exits the process.
		os.Args = append([]string{"godaemonhunter " + s.name}, args[1:]...)
		s.main(version, contractYML)
		return 0
	}
	fmt.Fprintf(os.Stderr, "godaemonhunter: unknown stream or sub-tool %q\n", args[0])
	usage()
	return 2
}

func usage() {
	names := make([]string, len(subs))
	for i, s := range subs {
		names[i] = s.name
	}
	fmt.Fprintln(os.Stderr, "usage: godaemonhunter                      (every stream — the default layered run, GODAEMONHUNTER_* driven)\n"+
		"       godaemonhunter <stream>...          (scope the run to byakugan-model streams: "+strings.Join(streamWords(), " ")+")\n"+
		"       godaemonhunter <subtool>            (one parser's env-driven batch: "+strings.Join(names, " ")+")\n"+
		"       godaemonhunter <subtool> <args>     (that parser's argv debug pass-through: -f FILE | -d DIR | --tar, -q)\n"+
		"       godaemonhunter --version | --print-contract")
}

// streamWords is the accepted stream vocabulary, sorted.
func streamWords() []string {
	w := make([]string, 0, len(streams))
	for k := range streams {
		w = append(w, k)
	}
	sort.Strings(w)
	return w
}

// huntSummary is hunt's single stdout JSON line: the aggregate roll-up
// with every subtool's own summary embedded.
type huntSummary struct {
	Tool         string          `json:"tool"`
	Version      string          `json:"version"`
	Pinfo        string          `json:"pinfo"`
	Status       string          `json:"status"`
	Inputs       int             `json:"inputs"`
	Processed    int             `json:"processed"`
	Skipped      int             `json:"skipped"`
	Failed       int             `json:"failed"`
	Records      int             `json:"records"`
	KnowledgeDir string          `json:"knowledge_dir"`
	Streams      []string        `json:"streams"`
	Images       []string        `json:"images,omitempty"`      // the disk images and collections run on, by item name
	Collections  []string        `json:"collections,omitempty"` // the UAC collections among them
	Live         string          `json:"live,omitempty"`        // the live host run on, by item name
	Subtools     []batch.Summary `json:"subtools"`
	Failures     []batch.Failure `json:"failures,omitempty"` // an image that could not be read
	Exit         int             `json:"exit"`
	Started      string          `json:"started"`
	DurationS    float64         `json:"duration_s"`
}

// runSubOnImage is one parser's batch mode over ONE disk image: linux-core is
// pulled into scratch, the batch loop runs over that tree, and the flattened
// records land at <OUT_DIR>/<asset-id>.jsonl; the parser's summary line is printed.
func runSubOnImage(s sub, selected string, getenv func(string) string, stdout io.Writer) int {
	pfx := batch.Prefix(s.tool.Name) + "_"
	get := func(suffix, def string) string {
		if v := getenv(pfx + suffix); v != "" {
			return v
		}
		return def
	}
	in, out, work := get("INPUT_DIR", "/input"), get("OUT_DIR", "/output"), get("WORK_DIR", "/work")
	images, err := selectedItems(in, selected)
	if err != nil {
		return configErrorSummary(s.name, err, stdout)
	}
	scratch, err := materialiseImage(getenv, work, images[0], imageSets)
	if err != nil {
		return configErrorSummary(s.name, err, stdout)
	}
	defer os.RemoveAll(scratch)
	return runFlat(s.tool, batch.Options{Version: version, Contract: contractYML}, getenv,
		map[string]string{"INPUT_DIR": scratch, "IMAGE": ""},
		out, work, scratch, diskimage.ImageItemName(in, images[0]), map[string]bool{}, stdout)
}

// runSubOnLive is one parser's batch mode on the live host: livecollect stages
// the artefact surface into scratch, the batch loop runs over that, and the
// flattened records land at <OUT_DIR>/<asset-id>.jsonl (the live host name);
// the parser's summary line is printed. LIVE and IMAGE are mutually exclusive.
func runSubOnLive(s sub, getenv func(string) string, stdout io.Writer) int {
	pfx := batch.Prefix(s.tool.Name) + "_"
	get := func(suffix, def string) string {
		if v := getenv(pfx + suffix); v != "" {
			return v
		}
		return def
	}
	if get("IMAGE", "") != "" {
		return configErrorSummary(s.name, fmt.Errorf("LIVE and IMAGE are mutually exclusive — a run is on one source"), stdout)
	}
	work, out := get("WORK_DIR", "/work"), get("OUT_DIR", "/output")
	res, item, err := stageLive(get, work, strings.EqualFold(get("LOG_LEVEL", "info"), "debug"))
	if err != nil {
		return configErrorSummary(s.name, err, stdout)
	}
	defer os.RemoveAll(res.Dir)
	return runFlat(s.tool, batch.Options{Version: version, Contract: contractYML}, getenv,
		map[string]string{"INPUT_DIR": res.Dir, "IMAGE": "", "LIVE": ""},
		out, work, res.Dir, item, map[string]bool{}, stdout)
}

// runSubBatch is one parser's plain env-driven batch mode — no image, no live:
// the loose-evidence case DX drives for a single sub-tool (e.g. a Layer-2 parser
// over one host's extracted artefacts). It runs through the flatten wrapper so
// the records land at <OUT_DIR>/<asset-id>.jsonl — one file, named by the
// manifest asset id or (loose, as here) the input host dir — instead of the
// runtime's <item>/<subtool>.jsonl tree. Any KNOWLEDGE_DIR the caller set falls
// through untouched (a loose Layer-2 run resolves against a prior Layer-1 store).
func runSubBatch(s sub, getenv func(string) string, stdout io.Writer) int {
	pfx := batch.Prefix(s.tool.Name) + "_"
	get := func(suffix, def string) string {
		if v := getenv(pfx + suffix); v != "" {
			return v
		}
		return def
	}
	out, in, work := get("OUT_DIR", "/output"), get("INPUT_DIR", "/input"), get("WORK_DIR", "/work")
	return runFlat(s.tool, batch.Options{Version: version, Contract: contractYML}, getenv,
		map[string]string{}, out, work, "", filepath.Base(in), map[string]bool{}, stdout)
}

// stageLive collects the live host's artefact surface into scratch and returns
// the stage plus the host item name. get reads the caller's variable block
// (GODAEMONHUNTER_* for the hunt, <SUBTOOL>_* for a sub-tool run): LIVE_ROOT
// (default /), LIVE_OS (default this host's GOOS) and LIVE_MAX_FILE (a byte
// cap, 0 = none).
func stageLive(get func(suffix, def string) string, work string, debug bool) (livecollect.Result, string, error) {
	root := get("LIVE_ROOT", "/")
	st, err := os.Stat(root)
	if err != nil {
		return livecollect.Result{}, "", fmt.Errorf("LIVE_ROOT %s: %w", root, err)
	}
	if !st.IsDir() {
		return livecollect.Result{}, "", fmt.Errorf("LIVE_ROOT %s: not a directory", root)
	}
	maxFile, err := parseMaxFile(get("LIVE_MAX_FILE", "0"))
	if err != nil {
		return livecollect.Result{}, "", err
	}
	item := liveItemName()
	var logf func(string, ...any)
	if debug {
		logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "godaemonhunter: live: "+format+"\n", args...)
		}
	}
	res, err := livecollect.Stage(livecollect.Options{
		Root: root, OS: get("LIVE_OS", runtime.GOOS), WorkDir: work,
		Item: item, MaxFile: maxFile, Logf: logf,
	})
	if err != nil {
		return livecollect.Result{}, "", err
	}
	fmt.Fprintf(os.Stderr, "godaemonhunter: live: staged %d files, %d bytes, %d skipped from %s [%s]\n",
		res.Files, res.Bytes, res.Skipped, root, res.OS)
	return res, item, nil
}

// liveItemName names the live host's output folder: the running host's name,
// folded to one safe path element, or "live" when it cannot be read.
func liveItemName() string {
	h, err := os.Hostname()
	if err != nil {
		return "live"
	}
	if h = strings.TrimSpace(h); h == "" {
		return "live"
	}
	return toolkit.FoldName("/", "/"+h)
}

// parseMaxFile reads LIVE_MAX_FILE: a non-negative byte count, 0 meaning no cap.
func parseMaxFile(s string) (int64, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("LIVE_MAX_FILE: %q is not a non-negative byte count", s)
	}
	return n, nil
}

// configErrorSummary prints a parser-shaped config_error summary line.
func configErrorSummary(tool string, err error, stdout io.Writer) int {
	fmt.Fprintf(os.Stderr, "godaemonhunter %s: %v\n", tool, err)
	sum := batch.Summary{Tool: tool, Version: version, Status: "config_error", Outputs: []string{},
		Error: err.Error(), Exit: 2, Started: time.Now().UTC().Format(time.RFC3339)}
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(sum)
	return 2
}

// runHunt executes the layered pipeline: Layer 1 into the knowledge dir,
// then Layer 2 with the store mounted, each subtool through the ordinary
// batch runtime under a shimmed environment. words are the stream words
// scoping Layer 2 (empty = every stream, the default); Layer 1 is never
// scoped — it is the knowledge store.
func runHunt(getenv func(string) string, stdout io.Writer, words []string) int {
	if len(words) == 0 {
		words = streamWords()
	} else {
		seen := map[string]bool{}
		uniq := words[:0]
		for _, w := range words {
			if !seen[w] {
				seen[w] = true
				uniq = append(uniq, w)
			}
		}
		words = uniq
		sort.Strings(words)
	}
	want := map[string]bool{}
	for _, w := range words {
		for _, name := range streams[w] {
			want[name] = true
		}
	}
	get := func(suffix, def string) string {
		if v := getenv("GODAEMONHUNTER_" + suffix); v != "" {
			return v
		}
		return def
	}
	in := get("INPUT_DIR", "/input")
	out := get("OUT_DIR", "/output")
	work := get("WORK_DIR", "/work")
	force := get("FORCE", "0")
	level := get("LOG_LEVEL", "info")
	kdir := get("KNOWLEDGE_DIR", filepath.Join(out, "knowledge"))

	started := time.Now()
	sum := &huntSummary{
		Tool: "godaemonhunter", Version: version, Pinfo: gopinfo.Version,
		KnowledgeDir: kdir, Streams: words, Subtools: []batch.Summary{},
		Started: started.UTC().Format(time.RFC3339),
	}

	// the passes: the one source this run is on. A live host (livecollect)
	// or one or more disk images (gomount) each become their own host —
	// knowledge per-item at <kdir>/<host>/, Layer-2 records flat at <OUT_DIR>/<subtool>/<asset-id>.jsonl —
	// and a loose tree (neither live nor image) is the input dir itself. LIVE
	// and IMAGE are mutually exclusive: a run is on one source.
	type pass struct{ in, host, scratch string }
	var passes []pass
	sawOK, sawPartial, sawConfig := false, false, false

	live, err := batch.ParseBool(get("LIVE", "0"))
	if err != nil {
		sum.Status, sum.Exit = "config_error", 2
		sum.Failures = []batch.Failure{{Item: "GODAEMONHUNTER_LIVE", Error: err.Error()}}
		fmt.Fprintf(os.Stderr, "godaemonhunter: GODAEMONHUNTER_LIVE: %v\n", err)
		return writeHunt(sum, started, stdout)
	}
	if live {
		if get("IMAGE", "") != "" {
			err := fmt.Errorf("LIVE and IMAGE are mutually exclusive — a run is on one source")
			sum.Status, sum.Exit = "config_error", 2
			sum.Failures = []batch.Failure{{Item: "live", Error: err.Error()}}
			fmt.Fprintf(os.Stderr, "godaemonhunter: %v\n", err)
			return writeHunt(sum, started, stdout)
		}
		res, host, err := stageLive(get, work, strings.EqualFold(level, "debug"))
		if err != nil {
			sum.Status, sum.Exit = "config_error", 2
			sum.Failures = []batch.Failure{{Item: "live", Error: err.Error()}}
			fmt.Fprintf(os.Stderr, "godaemonhunter: live: %v\n", err)
			return writeHunt(sum, started, stdout)
		}
		sum.Live = host
		passes = append(passes, pass{in: res.Dir, host: host, scratch: res.Dir})
	} else {
		selected := get("IMAGE", "")
		images, err := selectedItems(in, selected)
		if err != nil {
			sum.Status, sum.Exit = "config_error", 2
			sum.Failures = []batch.Failure{{Item: selected, Error: err.Error()}}
			fmt.Fprintf(os.Stderr, "godaemonhunter: %v\n", err)
			return writeHunt(sum, started, stdout)
		}
		if selected == "" {
			passes = append(passes, pass{in: in})
			// the UAC collections beside the disk images (imageitem.go)
			images = append(images, discoverCollections(getenv, in, work)...)
		}
		for _, img := range images {
			host := diskimage.ImageItemName(in, img)
			scratch, err := materialiseImage(getenv, work, img, imageSets)
			if err != nil {
				fmt.Fprintf(os.Stderr, "godaemonhunter: %s: %v\n", host, err)
				sum.Failed++
				sum.Failures = append(sum.Failures, batch.Failure{Item: img, Error: err.Error()})
				sawPartial = true
				continue
			}
			sum.Images = append(sum.Images, host)
			if isArchiveItem(img) {
				sum.Collections = append(sum.Collections, host)
			}
			passes = append(passes, pass{in: scratch, host: host, scratch: scratch})
		}
	}

	opened := map[string]bool{} // Layer-2 final files opened this hunt: first touch truncates, a later same-asset pass appends
	for _, p := range passes {
		hostKdir := filepath.Join(kdir, p.host)
		assetFallback := p.host
		if assetFallback == "" {
			assetFallback = filepath.Base(p.in)
		}
		for _, s := range subs {
			if s.layer == 2 && !want[s.name] {
				continue
			}
			var buf bytes.Buffer
			var code int
			if s.layer == 2 {
				// Layer-2 records flatten to <OUT_DIR>/<subtool>/<asset-id>.jsonl
				code = runFlat(s.tool, batch.Options{Version: version, Contract: contractYML}, getenv,
					map[string]string{"INPUT_DIR": p.in, "WORK_DIR": work, "FORCE": force, "LOG_LEVEL": level, "KNOWLEDGE_DIR": hostKdir, "IMAGE": ""},
					filepath.Join(out, s.name), work, p.scratch, assetFallback, opened, &buf)
			} else {
				// Layer-1 builds the per-item knowledge store (<kdir>/<host>) that
				// Layer 2 resolves against — an internal tree, left un-flattened.
				shim := shimEnv(s.tool, getenv, map[string]string{
					"INPUT_DIR": p.in, "OUT_DIR": hostKdir, "WORK_DIR": work,
					"FORCE": force, "LOG_LEVEL": level, "KNOWLEDGE_DIR": hostKdir, "IMAGE": "",
				})
				code = batch.Run(s.tool, batch.Options{Version: version, Contract: contractYML}, shim, &buf)
			}
			var ss batch.Summary
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &ss); err != nil {
				ss = batch.Summary{Tool: s.name, Status: "config_error", Exit: code}
			}
			if p.host != "" {
				ss.Subtool = p.host // which image this sub-run was
			}
			sum.Subtools = append(sum.Subtools, ss)
			sum.Inputs += ss.Inputs
			sum.Processed += ss.Processed
			sum.Skipped += ss.Skipped
			sum.Failed += ss.Failed
			sum.Records += ss.Records
			switch code {
			case 0:
				sawOK = true
			case 2:
				sawConfig = true
			case 3:
				sawPartial = true
				sawOK = true
			}
		}
		if p.scratch != "" {
			os.RemoveAll(p.scratch)
		}
	}
	switch {
	case sawConfig:
		sum.Status, sum.Exit = "config_error", 2
	case sawPartial:
		sum.Status, sum.Exit = "partial", 3
	case sawOK:
		sum.Status, sum.Exit = "ok", 0
	default:
		sum.Status, sum.Exit = "nothing", 1
	}
	return writeHunt(sum, started, stdout)
}

// writeHunt stamps the duration and prints the one aggregate line.
func writeHunt(sum *huntSummary, started time.Time, stdout io.Writer) int {
	sum.DurationS = float64(int64(time.Since(started).Seconds()*1000)) / 1000
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(sum); err != nil {
		fmt.Fprintf(os.Stderr, "godaemonhunter: write summary: %v\n", err)
		return 2
	}
	return sum.Exit
}

// shimEnv maps a subtool's reserved variables onto hunt's values while
// letting every other variable fall through to the real environment.
func shimEnv(t batch.Tool, getenv func(string) string, vals map[string]string) func(string) string {
	pfx := batch.Prefix(t.Name) + "_"
	return func(k string) string {
		if suffix, ok := strings.CutPrefix(k, pfx); ok {
			if v, set := vals[suffix]; set {
				return v
			}
		}
		return getenv(k)
	}
}
