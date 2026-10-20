package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func stageFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func lineCount(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(bytes.TrimRight(b, "\n"), []byte("\n")) + 1
}

// mergeFlat collapses the runtime's per-item tree into one <out>/<assetID>.jsonl:
// the first touch of a final file this run truncates, a later same-asset pass
// appends (two acquisitions of one disk merge), and a fresh run rebuilds.
func TestMergeFlat(t *testing.T) {
	out := t.TempDir()
	final := filepath.Join(out, "WD-WX11A.jsonl")
	opened := map[string]bool{}

	t1 := t.TempDir()
	stageFile(t, filepath.Join(t1, "a", "gosyslog.jsonl"), "{\"n\":1}\n")
	stageFile(t, filepath.Join(t1, "b", "gosyslog.jsonl"), "{\"n\":2}\n")
	outs, err := mergeFlat(t1, out, "WD-WX11A", opened)
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 1 || outs[0] != final {
		t.Fatalf("outs = %v, want [%s]", outs, final)
	}
	if n := lineCount(t, final); n != 2 {
		t.Fatalf("pass 1 lines = %d, want 2", n)
	}

	// same asset id: appends — the second acquisition merges, not clobbers
	t2 := t.TempDir()
	stageFile(t, filepath.Join(t2, "c", "gosyslog.jsonl"), "{\"n\":3}\n")
	if _, err := mergeFlat(t2, out, "WD-WX11A", opened); err != nil {
		t.Fatal(err)
	}
	if n := lineCount(t, final); n != 3 {
		t.Fatalf("same-asset append lines = %d, want 3", n)
	}

	// a fresh run (new opened set) truncates and rebuilds
	if _, err := mergeFlat(t2, out, "WD-WX11A", map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if n := lineCount(t, final); n != 1 {
		t.Fatalf("rebuild lines = %d, want 1 (truncate-first-touch)", n)
	}
}

func TestMergeFlatIgnoresPartAndEmpty(t *testing.T) {
	out := t.TempDir()

	// a crashed item the runtime did not rename is not merged
	tp := t.TempDir()
	stageFile(t, filepath.Join(tp, "x", "gosyslog.jsonl.part"), "{\"torn\":true}\n")
	outs, err := mergeFlat(tp, out, "ASSET", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 0 {
		t.Fatalf(".part merged: %v", outs)
	}
	if _, err := os.Stat(filepath.Join(out, "ASSET.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("a flat file was written from only a .part: %v", err)
	}

	// an empty temp (the parser matched nothing) writes nothing
	if outs, err := mergeFlat(t.TempDir(), out, "ASSET", map[string]bool{}); err != nil || len(outs) != 0 {
		t.Fatalf("empty temp: outs=%v err=%v", outs, err)
	}
}

// A csv-format run is not concatenable (per-table headers, disjoint schemas), so
// mergeFlat preserves those files verbatim under their relative path rather than
// joining them into a corrupt <asset-id>.csv.
func TestMergeFlatPreservesNonJSONL(t *testing.T) {
	out := t.TempDir()
	tmp := t.TempDir()
	stageFile(t, filepath.Join(tmp, "item1", "wtmp.csv"), "ts,user\n1,root\n")
	stageFile(t, filepath.Join(tmp, "item1", "btmp.csv"), "ts,fail\n2,x\n") // different schema
	stageFile(t, filepath.Join(tmp, "item1", "gowtmp.jsonl"), "{\"k\":\"wtmp\"}\n")

	outs, err := mergeFlat(tmp, out, "WD-WX11A", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "WD-WX11A.jsonl")); err != nil {
		t.Fatalf("jsonl not flattened: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "WD-WX11A.csv")); !os.IsNotExist(err) {
		t.Fatalf("csv files were concatenated into <asset-id>.csv: %v", err)
	}
	for _, rel := range []string{"item1/wtmp.csv", "item1/btmp.csv"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("csv not preserved at %s: %v", rel, err)
		}
	}
	if len(outs) != 3 {
		t.Fatalf("outs = %v, want the jsonl plus the two preserved csvs", outs)
	}
}
