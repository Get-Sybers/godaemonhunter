# `godaemonhunter gojournal` — the systemd journal (the Linux evtx)

Part of the Linux matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope and
rule-2 provenance stamping come from the module, not a copied `batch.go`.

Finds every binary journal under the input tree — `*.journal` files, the
archived `system@…​.journal` generations, per-user journals, and dirty
`*.journal~` files alike — and emits **one record per entry, streaming**:
entries are walked through the file's entry-array chain, so no journal is
ever held in memory whole. Data payloads compressed with XZ, LZ4 or ZSTD
(per-object flags) decode with pure-Go readers; **compact-mode** files
(systemd 252+) are supported; every offset and size is bounds-checked, so
a truncated or dirty journal yields what is readable — skipped entries are
counted and warned, never silently lost — rather than an error.

The reader is clean-room from systemd's documented file layout, and the
committed fixture generator is an independent implementation of the writer
side that the tests decode. Validation against a real journal corpus is
part of the DX_DFIR lane bring-up (docs/linux §7.2).

Fields stay the journal's own, verbatim (docs/linux §4.1): the well-known
set is lifted to named columns — `Message`, `Priority`, `Identifier`,
`PID`, `UID`, `GID`, `Comm`, `Exe`, `Cmdline`, `SystemdUnit`, `UserUnit`,
`Hostname`, `Transport`, `AuditSession` — and everything else rides in a
`Fields` map (capped at 128 keys; non-UTF-8 values are hex-prefixed, never
mangled). `(MachineID, BootID, Seqnum)` is the record's identity, carried
never minted; `__REALTIME` microseconds land in `EventTime`.

The journal is the **primary pathway for the typed event families**: on a
systemd host sshd, sudo, pam and cron all log through it (the flat
`auth.log` may not exist at all), so entries whose identifier and message
match are promoted by the shared `pinfo/families` engine — `sshd_event`,
`sudo_event`, `pam_session`, `cron_event` — carrying the family fields in
addition to every journal field, in exactly the shape gosyslog produces
from flat logs. One event, one shape, either source.

As `godaemonhunter gojournal` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode: it
reads the `GOJOURNAL_*` environment, finds every journal under the input
tree, writes one output folder per file and prints exactly one JSON
summary line on stdout.

## Input

The evidence tree at `GOJOURNAL_INPUT_DIR` (default `/input`), mounted
read-only. A `materialise.jsonl` manifest at the input root, when present,
is joined onto every record as `Origin`/`Snapshot`/`Residue`.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOJOURNAL_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOJOURNAL_OUT_DIR` | `/output` | output root, one folder per journal |
| `GOJOURNAL_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOJOURNAL_WORK_DIR` | `/work` | scratch (writable tmpfs); gojournal needs none but honours it |
| `GOJOURNAL_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOJOURNAL_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gojournal.jsonl`, one folder per journal
file; one `journal_entry` record per entry.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — work done, or already up-to-date and not forced |
| 1 | nothing produced — no journals found, or every item failed |
| 2 | config error — bad variable, missing input, unwritable output |
| 3 | partial — at least one item processed, at least one failed |

## Run

```sh
docker build -t get-sybers/godaemonhunter:latest -f godaemonhunter/Dockerfile .
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
  -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/godaemonhunter:latest gojournal
```

(Build from the **repo root**: the image copies the sibling `pinfo/`
module; the pinned pure-Go decompressors ride `go.mod`/`go.sum`.)

## argv pass-through (debug only, `godaemonhunter gojournal <args>`)

`-f FILE | -d DIR`, `-q`; records stream to stdout.
Exit 0 ok / 1 usage or fatal / 2 at least one file failed. `--version`
prints the version; `--print-contract` prints `contract.yml`.
