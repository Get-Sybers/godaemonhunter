# `godaemonhunter gowtmp` — Linux login records (utmp/wtmp/btmp/lastlog)

The P0 pilot of the Linux matrix ([docs/linux](../../docs/linux/README.md)) and
the first tool on the shared [`pinfo`](../../pinfo) module: batch runtime,
record envelope, and rule-2 provenance stamping come from the module, not a
copied `batch.go`.

Parses the classic glibc binary login records:

- **utmp / wtmp / btmp** — 384-byte `struct utmp` entries: wtmp is the login
  history, `/var/run/utmp` the live table, btmp the failed logins. Rotations
  (`wtmp.1`, `wtmp-20260901`) and gzip (content-detected, not by name) are
  read transparently. EMPTY (type 0) slots are skipped; every other record
  type is emitted with its native 1–9 vocabulary verbatim — mapping
  6/7→login, 8→logout is byakugan's call, not the parser's.
- **lastlog** — the sparse per-UID last-login table (292-byte slots, the UID
  is the slot index). Only populated slots emit; uid 0 is a real value.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, `EventTime` UTC, `TimeKind`, and
`Origin`/`Snapshot`/`Residue` when a stage manifest resolves them). The
utmp payload carries the full `l2t_utmp` field floor: `Username`,
`Hostname` (the login *source* host), `IPAddress` (IPv4/IPv6 from
`ut_addr_v6`), `PID`, `Terminal`, `TerminalID`, `ExitTermination`,
`ExitStatus`, `Session`, `LoginType`(+`Name`). Non-glibc record layouts are
rejected with an error, never misparsed.

As `godaemonhunter gowtmp` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode
([`contract.yml`](../contract.yml)): it reads `GOWTMP_INPUT_DIR` /
`GOWTMP_OUT_DIR` / `GOWTMP_FORCE` / `GOWTMP_LOG_LEVEL`,
finds every utmp-family file under the input tree, writes one output folder
per file and prints exactly one JSON summary line on stdout (exit 0 success ·
1 nothing · 2 config error · 3 partial).

## Input

The evidence tree at `GOWTMP_INPUT_DIR` (default `/input`), mounted
read-only: a staged `linux-core` materialise tree, a loose `/var/log`
collection, or any directory holding utmp-family files. A
`materialise.jsonl` manifest at the input root, when present, is joined onto
every record as `Origin`/`Snapshot`/`Residue` — the tool computes no
provenance itself.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOWTMP_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOWTMP_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOWTMP_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOWTMP_WORK_DIR` | `/work` | scratch (writable tmpfs); gowtmp needs none but honours it |
| `GOWTMP_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOWTMP_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gowtmp.jsonl`, one
folder per input file; `<item>` is the input-relative path with separators
folded to `_`. One record per utmp entry / populated lastlog slot.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — work done, or already up-to-date and not forced |
| 1 | nothing produced — no utmp-family files found, or every item failed |
| 2 | config error — bad variable, missing input, unwritable output |
| 3 | partial — at least one item processed, at least one failed |

## Run

```sh
docker build -t get-sybers/godaemonhunter:latest -f godaemonhunter/Dockerfile .
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
  -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/godaemonhunter:latest gowtmp
```

(Build from the **repo root**: the image copies the sibling `pinfo/` module.)

## argv pass-through (debug only, `godaemonhunter gowtmp <args>`)

`-f FILE | -d DIR | --tar` (a `gomount stream` tar on stdin), `-q`; records stream to stdout. Exit 0 ok / 1 usage or fatal / 2
at least one file failed. `--version` prints the version;
`--print-contract` prints `contract.yml`.
