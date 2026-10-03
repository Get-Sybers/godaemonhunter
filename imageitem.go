// Disk images as items. The parsers read artefact FILES; a disk image under
// the input tree is not one, it holds them. This file makes the image the
// item: the artefact sets the selected parsers read are pulled out of the
// image's OS volume by the baked-in gomount (materialise — no mount, no FUSE,
// no privilege, the image opened read-only) into a scratch tree under the
// work dir, the ordinary batch loop runs over that tree exactly as it would
// over a loose evidence folder, the records land under <OUT_DIR>/…/<image>/,
// and the scratch tree goes. Nothing is exported to the output tree: the
// parsers run on the image.
//
// Selection: GODAEMONHUNTER_IMAGE (a sub-tool run: <SUBTOOL>_IMAGE) names ONE
// image relative to INPUT_DIR; empty means every disk image found directly
// under INPUT_DIR (an EWF set's first segment, a VMDK descriptor or
// monolithic extent — never a -flat/-sNNN extent or an .E02… segment) plus,
// for the hunt, the loose tree itself.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Get-Sybers/gopinfo/diskimage"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// macSystemSets is what the second pass pulls off a Mac's sealed System
// volume when the volume gomount selected for the image is the Data
// volume (macOS 10.15+ keeps the OS apart from the user data): the OS
// version and Apple's own launchd jobs.
var macSystemSets = []string{"macos-system"}

// materialiseImage pulls the artefact sets out of image into the scratch
// tree <work>/<image item> and returns it. The name is deterministic — the
// records' origin paths read <work>/<image>/<volume path>, and a tree a
// killed run left behind is cleared before the pull. gomount's exit 1
// (nothing on the volume matched) is not an error: the tree is simply empty
// and the parsers find nothing, like a loose folder without their artefact.
func materialiseImage(getenv func(string) string, work, image string, sets []string) (string, error) {
	scratch := filepath.Join(work, diskimage.ImageItemName(filepath.Dir(image), image))
	if err := os.RemoveAll(scratch); err != nil {
		return "", fmt.Errorf("clear scratch %s: %w", scratch, err)
	}
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		return "", fmt.Errorf("scratch under %s: %w", work, err)
	}
	// --manifest: the origin record of every staged file (rule 2), which
	// the batch runtime joins onto the records as Origin
	if err := runMaterialise(getenv, scratch, image, sets, 0); err != nil {
		os.RemoveAll(scratch)
		return "", err
	}
	if err := materialiseMacSystem(getenv, scratch, image); err != nil {
		// the second pass is best-effort: the Data volume's surface is
		// staged, the System volume's is reported and skipped
		fmt.Fprintf(os.Stderr, "godaemonhunter: %s: system volume: %v\n", filepath.Base(image), err)
	}
	return scratch, nil
}

// runMaterialise pulls sets from the image (volume 0 = gomount's choice)
// into out with a manifest. gomount's exit 1 (nothing matched) is not an
// error.
func runMaterialise(getenv func(string) string, out, image string, sets []string, volume int) error {
	args := []string{"materialise", "--out", out, "--manifest"}
	if volume > 0 {
		args = append(args, "--volume", strconv.Itoa(volume))
	}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	args = append(args, image)
	cmd := exec.Command(diskimage.GomountPath(getenv), args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = nil // its summary line is not ours to print
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return nil // nothing pulled
		}
		return fmt.Errorf("gomount materialise %s: %w", filepath.Base(image), err)
	}
	return nil
}

// identifiedVolume is the slice of gomount identify's volume rows this
// file reads: the --volume index and the OS guess.
type identifiedVolume struct {
	Volume int    `json:"volume"`
	Source string `json:"source"`
	OS     string `json:"os"`
}

// identifyVolumes asks gomount for the image's resolved stack.
func identifyVolumes(getenv func(string) string, image string) ([]identifiedVolume, error) {
	cmd := exec.Command(diskimage.GomountPath(getenv), "identify", image)
	cmd.Stderr = nil
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var doc struct {
		Volumes []identifiedVolume `json:"volumes"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	return doc.Volumes, nil
}

// materialiseMacSystem is the second pass of a modern Mac: when the stack
// holds both a Data volume (what the first pass read) and a System
// volume, the System volume's version plist and Apple's launchd jobs are
// pulled into a side tree and merged into the scratch — files the Data
// side already staged are left as they are, the manifest rows are
// appended (each row names its own volume, so provenance stays exact).
// An image without that pair, or a gomount without identify, is left as
// the first pass staged it.
func materialiseMacSystem(getenv func(string) string, scratch, image string) error {
	vols, err := identifyVolumes(getenv, image)
	if err != nil {
		return nil // no stack to consult: nothing to add
	}
	data, system := 0, 0
	for _, v := range vols {
		switch v.OS {
		case "macos (data)":
			if data == 0 {
				data = v.Volume
			}
		case "macos (system)":
			if system == 0 {
				system = v.Volume
			}
		}
	}
	if data == 0 || system == 0 {
		return nil
	}
	side := scratch + ".system"
	if err := os.RemoveAll(side); err != nil {
		return err
	}
	if err := os.MkdirAll(side, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(side)
	if err := runMaterialise(getenv, side, image, macSystemSets, system); err != nil {
		return err
	}
	return mergeStage(side, scratch)
}

// mergeStage moves every staged file of src that dst lacks into dst and
// appends src's manifest rows to dst's.
func mergeStage(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if rel == "materialise.jsonl" {
			return appendFile(p, filepath.Join(dst, rel))
		}
		target := filepath.Join(dst, rel)
		if _, err := os.Lstat(target); err == nil {
			return nil // the Data side's copy stands
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.Rename(p, target); err != nil {
			return copyFile(p, target)
		}
		return nil
	})
}

// appendFile appends src's lines to dst (creating it), so two manifests
// become one.
func appendFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			if _, err := out.WriteString(line + "\n"); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

// copyFile is the cross-device fallback of the merge.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o400)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chtimes(dst, st.ModTime(), st.ModTime())
}
