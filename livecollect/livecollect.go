// Package livecollect stages the live-system artefact surface into a tree the
// ordinary batch loop can run over — the live-host counterpart of the disk-image
// materialise (imageitem.go, gopinfo/diskimage). A disk image is a host too:
// gomount pulls the linux-core / macos-core artefact set out of its OS volume
// into a scratch tree and the layered pipeline runs over that. A live system is
// a host too — only the source is the running root filesystem instead of an
// image, so there is no gomount and no decode: this package copies the same
// artefact surface out of the live root into the scratch tree, then main runs
// the unchanged pipeline over it.
//
// Why stage at all, rather than point INPUT_DIR at `/`: every parser discovers
// its files with a single filepath.WalkDir of the whole input root, and that
// walk aborts the run as a config error on the first unreadable directory
// (gopinfo/discover.Files, gopinfo/batch). A live `/` would descend /proc,
// /sys, /dev and every mounted filesystem and die on the first permission
// denial. Staging visits only the known artefact trees (profiles.json), is
// resilient to per-file read failures — a vanished or unreadable file is logged
// and skipped, never fatal — and captures a point-in-time snapshot of volatile
// logs, which is the forensically correct behaviour for a running host.
//
// The artefact set is data, not code (docs/standards go §5): profiles.json
// holds one OS-keyed profile — the system trees to copy and the per-home
// artefacts to collect from each account — so adding macOS, or tuning a path,
// is a data change. Each staged file gets a rule-2 provenance row in
// materialise.jsonl at the scratch root (the same manifest the batch runtime
// joins onto records): its real on-host path as Origin.Path, its inode, and no
// Snapshot — absent means the live volume (gopinfo/record).
package livecollect

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed profiles.json
var profilesJSON []byte

// Profile is one operating system's live-collection surface: the system trees
// copied wholesale and the artefacts collected from each user home. It is
// reference data decoded from profiles.json, never a literal in code.
type Profile struct {
	OS    string `json:"os"`
	Trees []Tree `json:"trees"`
	Homes Homes  `json:"homes"`
}

// Tree is one source location relative to the live root, copied into the stage
// at the same relative path. A directory is copied recursively; a single file
// is copied on its own. The note documents which parsers the tree feeds.
type Tree struct {
	Path string `json:"path"`
	Note string `json:"note,omitempty"`
}

// Homes names the per-account artefacts: Roots are globs (relative to the live
// root) whose every matching directory is a home, and Artefacts are the paths —
// files or directories — collected from inside each one.
type Homes struct {
	Roots     []string `json:"roots"`
	Artefacts []string `json:"artefacts"`
}

// Profiles decodes and validates the embedded profile set, keyed by GOOS.
func Profiles() (map[string]Profile, error) {
	var profs map[string]Profile
	if err := json.Unmarshal(profilesJSON, &profs); err != nil {
		return nil, fmt.Errorf("decode profiles.json: %w", err)
	}
	for key, p := range profs {
		if err := validate(key, p); err != nil {
			return nil, err
		}
	}
	return profs, nil
}

// SupportedOS lists the operating systems a profile exists for, sorted — the
// vocabulary LIVE_OS accepts and the list an unsupported host is told.
func SupportedOS() []string {
	profs, err := Profiles()
	if err != nil {
		return nil
	}
	oses := make([]string, 0, len(profs))
	for k := range profs {
		oses = append(oses, k)
	}
	sort.Strings(oses)
	return oses
}

// validate holds profiles.json to its invariants: a profile is keyed by its own
// OS, carries something to collect, and every path is a clean relative path
// (the stage mirrors it, so an absolute or climbing path would escape).
func validate(key string, p Profile) error {
	if p.OS != key {
		return fmt.Errorf("profile %q: os field is %q, must match the key", key, p.OS)
	}
	if len(p.Trees) == 0 && len(p.Homes.Artefacts) == 0 {
		return fmt.Errorf("profile %q: no trees and no home artefacts", key)
	}
	check := func(what, rel string) error {
		if rel == "" {
			return fmt.Errorf("profile %q: empty %s path", key, what)
		}
		if clean := path.Clean(rel); strings.HasPrefix(rel, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("profile %q: %s path %q is not a clean relative path", key, what, rel)
		}
		return nil
	}
	for _, t := range p.Trees {
		if err := check("tree", t.Path); err != nil {
			return err
		}
	}
	for _, r := range p.Homes.Roots {
		if err := check("home root", r); err != nil {
			return err
		}
	}
	for _, a := range p.Homes.Artefacts {
		if err := check("home artefact", a); err != nil {
			return err
		}
	}
	return nil
}

// Options drives one live collection.
type Options struct {
	Root    string               // the live root to collect from (default "/")
	OS      string               // the profile to use (a GOOS: "linux", "darwin")
	WorkDir string               // scratch parent; the stage is <WorkDir>/<Item>
	Item    string               // stage folder name and provenance item (default "live")
	MaxFile int64                // per-file size cap in bytes; 0 = no cap
	Logf    func(string, ...any) // optional per-file skip/debug log; may be nil
}

// Result reports what a collection staged.
type Result struct {
	Dir     string // the stage root — the INPUT_DIR the pipeline then runs over
	OS      string // the profile used
	Files   int    // files staged
	Bytes   int64  // bytes copied
	Skipped int    // artefacts present but skipped (unreadable, over cap, write error)
}

// Stage copies opt.OS's artefact surface out of opt.Root into a fresh scratch
// tree under opt.WorkDir and writes its materialise.jsonl. A tree a killed run
// left behind is cleared first, so the stage name is reusable and deterministic.
// Per-file failures are logged and counted, never returned: the only errors are
// setup failures (no profile for the OS, an unusable work dir), which the caller
// turns into a config error.
func Stage(opt Options) (Result, error) {
	if opt.Root == "" {
		opt.Root = "/"
	}
	if opt.Item == "" {
		opt.Item = "live"
	}
	profs, err := Profiles()
	if err != nil {
		return Result{}, err
	}
	prof, ok := profs[opt.OS]
	if !ok {
		return Result{}, fmt.Errorf("no live-collection profile for %q (have %s)", opt.OS, strings.Join(SupportedOS(), ", "))
	}

	scratch := filepath.Join(opt.WorkDir, foldItem(opt.Item))
	if err := os.RemoveAll(scratch); err != nil {
		return Result{}, fmt.Errorf("clear stage %s: %w", scratch, err)
	}
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		return Result{}, fmt.Errorf("stage under %s: %w", opt.WorkDir, err)
	}

	mf, err := os.Create(filepath.Join(scratch, manifestName))
	if err != nil {
		os.RemoveAll(scratch)
		return Result{}, fmt.Errorf("stage manifest: %w", err)
	}
	enc := json.NewEncoder(mf)
	enc.SetEscapeHTML(false)

	// realRoot is the live root with its own symlinks resolved — the boundary a
	// followed symlink must stay inside. When it cannot be resolved the copy
	// still never follows a symlinked directory, so the containment check simply
	// degrades to that.
	realRoot, _ := filepath.EvalSymlinks(opt.Root)

	s := &stager{
		root: opt.Root, realRoot: realRoot, scratch: scratch, max: opt.MaxFile,
		logf: opt.Logf, enc: enc, seen: map[[2]uint64]bool{},
	}
	// a manifest-level metadata row: records whose per-file row does not say
	// otherwise are marked as coming from the live volume.
	s.meta(mrow{Volume: "live"})

	for _, t := range prof.Trees {
		s.copyTree(t.Path)
	}
	s.collectHomes(prof.Homes)

	flushErr := mf.Close()
	if flushErr != nil {
		return Result{}, fmt.Errorf("write stage manifest: %w", flushErr)
	}
	return Result{Dir: scratch, OS: prof.OS, Files: s.files, Bytes: s.bytes, Skipped: s.skipped}, nil
}

// stager carries one collection's state through the copy routines.
type stager struct {
	root     string
	realRoot string
	scratch  string
	max      int64
	logf     func(string, ...any)
	enc      *json.Encoder
	seen     map[[2]uint64]bool // (dev,inode) already staged — usrmerge/overlap dedup
	files    int
	bytes    int64
	skipped  int
}

func (s *stager) log(format string, args ...any) {
	if s.logf != nil {
		s.logf(format, args...)
	}
}

// copyTree stages one profile tree or home artefact. The root is classified by
// its own lstat: a symlink is handled as stageSymlink would any symlink — a
// file target followed, a directory target skipped — a plain directory is
// walked, and a plain file is copied. A symlinked directory is therefore never
// walked, whether it is a tree root or an entry inside one, so a
// user-controlled artefact (a home's .config/systemd/user, .bash_sessions, …)
// cannot redirect the collection at /, /proc or another mount. An intermediate
// path symlink the OS resolves on its own is fine: a /lib -> /usr/lib root
// reaches a real systemd/ directory and is walked, deduped by inode against
// usr/lib/systemd.
func (s *stager) copyTree(rel string) {
	src := filepath.Join(s.root, filepath.FromSlash(rel))
	li, err := os.Lstat(src)
	if err != nil {
		s.log("skip %s: %v", rel, err)
		return
	}
	switch {
	case li.Mode()&fs.ModeSymlink != 0:
		s.stageSymlink(rel, src)
		return
	case !li.IsDir():
		s.copyRegular(rel, src, li)
		return
	}
	filepath.WalkDir(src, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			s.log("skip %s: %v", p, werr) // unreadable dir/file — skip, never fatal
			return nil
		}
		if d.IsDir() {
			return nil
		}
		childRel := rel
		if p != src {
			sub, rerr := filepath.Rel(src, p)
			if rerr != nil {
				return nil
			}
			childRel = path.Join(rel, filepath.ToSlash(sub))
		}
		s.stageEntry(childRel, p, d.Type())
		return nil
	})
}

// collectHomes stages each home artefact from every directory a home root glob
// matches. An artefact is copied exactly as a tree is, so a directory artefact
// (.ssh, .bash_sessions, .config/systemd/user) comes across whole.
func (s *stager) collectHomes(h Homes) {
	for _, root := range h.Roots {
		matches, err := filepath.Glob(filepath.Join(s.root, filepath.FromSlash(root)))
		if err != nil {
			s.log("skip home root %s: %v", root, err)
			continue
		}
		sort.Strings(matches)
		for _, home := range matches {
			fi, err := os.Stat(home)
			if err != nil || !fi.IsDir() {
				continue
			}
			rel, err := filepath.Rel(s.root, home)
			if err != nil {
				continue
			}
			base := filepath.ToSlash(rel)
			for _, a := range h.Artefacts {
				s.copyTree(path.Join(base, a))
			}
		}
	}
}

// stageEntry stages one walked entry by its lstat type: a symlink specially, a
// regular file by copying it, everything else (socket, device, fifo) skipped.
func (s *stager) stageEntry(rel, src string, typ fs.FileMode) {
	switch {
	case typ&fs.ModeSymlink != 0:
		s.stageSymlink(rel, src)
	case typ.IsRegular():
		if fi, err := os.Lstat(src); err == nil {
			s.copyRegular(rel, src, fi)
		}
	}
}

// stageSymlink preserves a symlink as the evidence wants it. For localtime the
// zone name lives in the target, not the TZif content, so the target string is
// staged verbatim — the gohost parser reads the zone after "zoneinfo/", exactly
// as it does for an image-staged link. Every other symlink is followed only to
// a regular file inside the live root and its content copied (so
// /etc/os-release -> /usr/lib/os-release stages the real os-release). A symlink
// to a directory is never followed — the collection stays in the known trees
// and cannot be redirected at /, /proc or another mount — and a target that
// resolves outside the live root (an absolute link in a bind-mounted host tree
// pointing back at the collecting host) is not ours to copy.
func (s *stager) stageSymlink(rel, src string) {
	target, err := os.Readlink(src)
	if err != nil {
		s.log("skip %s: %v", rel, err)
		return
	}
	if filepath.Base(rel) == "localtime" {
		s.writeText(rel, src, target)
		return
	}
	real, err := filepath.EvalSymlinks(src)
	if err != nil {
		s.log("skip dangling %s -> %s", rel, target)
		return
	}
	if s.realRoot != "" && !withinRoot(s.realRoot, real) {
		s.log("skip %s: target %s escapes the live root", rel, real)
		return
	}
	fi, err := os.Stat(real)
	if err != nil {
		s.log("skip %s: %v", rel, err)
		return
	}
	if fi.IsDir() || !fi.Mode().IsRegular() {
		return
	}
	s.copyRegular(rel, real, fi)
}

// copyRegular copies one file into the stage, deduped by (dev,inode) so a file
// reached by two paths (a /lib -> /usr/lib usrmerge symlink, overlapping trees)
// is staged once, and capped by MaxFile when set. The original mtime is kept so
// the record's SourceModified is the artefact's, not the copy's.
func (s *stager) copyRegular(rel, src string, fi fs.FileInfo) {
	dev, ino, keyed := statKey(fi)
	if keyed {
		k := [2]uint64{dev, ino}
		if s.seen[k] {
			return
		}
		s.seen[k] = true
	}
	if s.max > 0 && fi.Size() > s.max {
		s.log("skip %s: %d bytes over cap %d", rel, fi.Size(), s.max)
		s.skipped++
		return
	}
	in, err := os.Open(src)
	if err != nil {
		s.log("skip %s: %v", rel, err)
		s.skipped++
		return
	}
	defer in.Close()
	dst := filepath.Join(s.scratch, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		s.log("skip %s: %v", rel, err)
		s.skipped++
		return
	}
	out, err := os.Create(dst)
	if err != nil {
		s.log("skip %s: %v", rel, err)
		s.skipped++
		return
	}
	n, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(dst)
		s.log("skip %s: %v", rel, firstErr(copyErr, closeErr))
		s.skipped++
		return
	}
	os.Chtimes(dst, time.Time{}, fi.ModTime())
	s.row(rel, ino)
	s.files++
	s.bytes += n
}

// writeText stages verbatim text (a captured symlink target) as the file's
// content.
func (s *stager) writeText(rel, src, text string) {
	dst := filepath.Join(s.scratch, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		s.log("skip %s: %v", rel, err)
		s.skipped++
		return
	}
	if err := os.WriteFile(dst, []byte(text), 0o644); err != nil {
		s.log("skip %s: %v", rel, err)
		s.skipped++
		return
	}
	var ino uint64
	if li, err := os.Lstat(src); err == nil {
		_, ino, _ = statKey(li)
	}
	s.row(rel, ino)
	s.files++
	s.bytes += int64(len(text))
}

// mrow is one materialise.jsonl line: a metadata row carries volume only, a
// file row the on-host path, its staged location and inode.
type mrow struct {
	Volume string `json:"volume,omitempty"`
	Path   string `json:"path,omitempty"`
	Staged string `json:"staged,omitempty"`
	Inode  uint64 `json:"inode,omitempty"`
}

func (s *stager) meta(r mrow) { s.enc.Encode(r) }

// row records a staged file's provenance: Path is its real on-host absolute
// path (independent of where Root pointed), Staged the lookup key the runtime
// joins on.
func (s *stager) row(rel string, ino uint64) {
	s.enc.Encode(mrow{Path: "/" + rel, Staged: rel, Inode: ino})
}

const manifestName = "materialise.jsonl"

// foldItem sanitises an item name for use as a single path element.
func foldItem(item string) string {
	var b strings.Builder
	for _, r := range item {
		if r == '/' || r == '\\' || r == ':' || r == 0 || r == ' ' {
			b.WriteByte('_')
		} else {
			b.WriteRune(r)
		}
	}
	if s := b.String(); s != "" && s != "." && s != ".." {
		return s
	}
	return "live"
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// withinRoot reports whether target (a resolved path) stays inside root (the
// resolved live root): a followed symlink must not leave the tree being
// collected. A component merely starting with ".." (a file literally named
// "..x") is inside; only "." and a path that climbs out ("..", "../…") count.
func withinRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
