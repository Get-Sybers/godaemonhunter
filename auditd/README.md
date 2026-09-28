# `godaemonhunter goauditd` — Linux audit log events

Part of the Linux matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope and
rule-2 provenance stamping come from the module, not a copied `batch.go`.

Finds every `audit.log` (rotations and gzip, content-detected) under the
input tree and emits **one record per event**: consecutive records sharing
an `audit(sec.msec:serial)` id — `SYSCALL` + `EXECVE` + `CWD` + `PATH` +
`PROCTITLE`, and the `USER_*`/`SERVICE_*` families — are coalesced.
Hex-encoded values (proctitle, execve args, comm) are decoded; execve argv
is reassembled in order; the kernel's milliseconds land in `EventTime`.
Everything stays native (docs/linux §4.1): record types verbatim in
`Types`, the syscall number as logged (a rendered `SyscallName` added for
the x86_64 table), numeric uids verbatim — resolution is enrichment and
byakugan's. `AuditID` is the record's identity field, carried never
minted. The execve stream is the CAR `process` feed.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, `EventTime` UTC, `TimeKind`, and
`Origin`/`Snapshot`/`Residue` when a stage manifest resolves them). The
declared record fields are in [`contract.yml`](../contract.yml).

As `godaemonhunter goauditd` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode: it
reads the `GOAUDITD_*` environment, finds every audit log under the input
tree, writes one output folder per file and prints exactly one JSON
summary line on stdout.

## Input

The evidence tree at `GOAUDITD_INPUT_DIR` (default `/input`), mounted
read-only. A `materialise.jsonl` manifest at the input root, when present,
is joined onto every record as `Origin`/`Snapshot`/`Residue`.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOAUDITD_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOAUDITD_OUT_DIR` | `/output` | output root, one folder per audit log |
| `GOAUDITD_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOAUDITD_WORK_DIR` | `/work` | scratch (writable tmpfs); goauditd needs none but honours it |
| `GOAUDITD_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOAUDITD_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/goauditd.jsonl`, one folder per audit log;
one `auditd_event` record per coalesced event.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — work done, or already up-to-date and not forced |
| 1 | nothing produced — no audit logs found, or every item failed |
| 2 | config error — bad variable, missing input, unwritable output |
| 3 | partial — at least one item processed, at least one failed |

## Run

```sh
docker build -t get-sybers/godaemonhunter:latest -f godaemonhunter/Dockerfile .
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
  -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/godaemonhunter:latest goauditd
```

(Build from the **repo root**: the image copies the sibling `pinfo/` module.)

## argv pass-through (debug only, `godaemonhunter goauditd <args>`)

`-f FILE | -d DIR`, `-q`; records stream to stdout.
Exit 0 ok / 1 usage or fatal / 2 at least one file failed. `--version`
prints the version; `--print-contract` prints `contract.yml`.
