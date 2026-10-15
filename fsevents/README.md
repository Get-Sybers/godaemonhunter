# `godaemonhunter gofsevents` — macOS fseventsd (filesystem change history)

Part of the macOS matrix ([docs/linux](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/docs/linux/README.md)), built on
the shared [`pinfo`](https://github.com/Get-Sybers/gopinfo) module: batch runtime, record envelope and
rule-2 provenance stamping come from the module, not a copied `batch.go`.

Reads the DLS logs under a volume's `/.fseventsd/` directory — the
gzip-compressed, per-volume record of filesystem changes the kernel's fsevents
writes — and emits one record per change: the `Path` (relative to the volume
root), the `EventID` (the monotonic fsevents counter), the raw DLS `Flags` word
and the `NodeID` (the file's inode; 2SLD/3SLD pages). The `fseventsd-uuid` and
`no_log` markers the directory also holds are not logs and are skipped; an
empty-path record is page padding and is skipped.

Rules (docs/linux §4.1): fseventsd carries no per-record wall-clock time — the
event id is an ordering counter, not a timestamp — so `EventTime` is left
unset; the id orders the changes and the containing log's own `SourceModified`
brackets them. `Flags` is the raw DLS flag word: decoding its reason/type bits
into names is byakugan's job (native verbatim, resolution is enrichment's). No
user or volume is derived here.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, and `Origin`/`Snapshot`/`Residue` when a
stage manifest resolves them). The declared record fields are in
[`contract.yml`](../contract.yml).

As `godaemonhunter gofsevents` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode: it
reads the `GOFSEVENTS_*` environment, finds every DLS log under the input
tree's `/.fseventsd/`, writes one output folder per file and prints exactly one
JSON summary line on stdout.

## Input

The evidence tree at `GOFSEVENTS_INPUT_DIR` (default `/input`), mounted
read-only: a staged `macos-core` materialise tree or any loose collection
holding a `/.fseventsd/` directory. A `materialise.jsonl` manifest at the input
root, when present, is joined onto every record as `Origin`/`Snapshot`/`Residue`.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOFSEVENTS_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOFSEVENTS_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOFSEVENTS_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOFSEVENTS_WORK_DIR` | `/work` | scratch (writable tmpfs); gofsevents needs none but honours it |
| `GOFSEVENTS_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOFSEVENTS_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gofsevents.jsonl`, one folder per DLS log.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — work done, or already up-to-date and not forced |
| 1 | nothing produced — no inputs found, or every item failed |
| 2 | config error — bad variable, missing input, unwritable output |
| 3 | partial — at least one item processed, at least one failed |

## Run

```sh
go install github.com/Get-Sybers/godaemonhunter@latest   # -> $(go env GOPATH)/bin/godaemonhunter

GOFSEVENTS_INPUT_DIR=./in GOFSEVENTS_OUT_DIR=./out godaemonhunter gofsevents
```

## argv pass-through (debug only, `godaemonhunter gofsevents <args>`)

`-f FILE | -d DIR`, `-q`; records stream to stdout. Exit 0 ok / 1 usage or
fatal / 2 at least one file failed. `--version` prints the version;
`--print-contract` prints `contract.yml`.
