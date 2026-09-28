# `godaemonhunter gosyslog` — syslog-family text logs

Part of the Linux matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope and
rule-2 provenance stamping come from the module, not a copied `batch.go`.

Finds `syslog`, `messages`, `auth.log`, `secure`, `kern.log`,
`cron`, `daemon.log`, `mail.log`, `user.log`, `debug` and their
rotations (gzip content-detected) and emits one record per line. Three
timestamp dialects are normalised to UTC `EventTime`: classic RFC3164
yearless prefixes (year inferred against the file's mtime, walking back
across New Year; recorded naive-as-UTC — the imaged host's zone is
byakugan-side context), ISO-8601 prefixes, and RFC5424 frames. The
`ident[pid]:` tag is split out; lines with no timestamp prefix
(continuations) are kept untyped with the raw line.

High-value families are **typed by the shared `pinfo/families` engine**
(docs/linux §4.1 rule 1) — the same engine gojournal feeds, because on a
systemd host the journal is the primary pathway for these events and the
flat logs are the fallback; either source yields one shape, so byakugan
maps select rows by predicates over typed fields instead of regexing
messages: `sshd_event` (authentication results with method,
account, source address/port, key type and fingerprint), `sudo_event`
(invoking account, target user, TTY, PWD, command), `pam_session`
(open/close with the invoking uid), and `cron_event` (job owner and
command). The raw line rides on every record.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, `EventTime` UTC, `TimeKind`, and
`Origin`/`Snapshot`/`Residue` when a stage manifest resolves them). The
declared record fields are in [`contract.yml`](../contract.yml).

As `godaemonhunter gosyslog` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode: it
reads the `GOSYSLOG_*` environment, finds every artefact it handles under the
input tree, writes one output folder per file and prints exactly one JSON
summary line on stdout.

## Input

The evidence tree at `GOSYSLOG_INPUT_DIR` (default `/input`), mounted
read-only: a staged `linux-core` materialise tree or any loose collection.
A `materialise.jsonl` manifest at the input root, when present, is joined
onto every record as `Origin`/`Snapshot`/`Residue`.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOSYSLOG_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOSYSLOG_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOSYSLOG_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOSYSLOG_WORK_DIR` | `/work` | scratch (writable tmpfs); gosyslog needs none but honours it |
| `GOSYSLOG_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOSYSLOG_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gosyslog.jsonl`, one folder per log file;
one record per line, `RecordType` `syslog_line` or a typed family.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — work done, or already up-to-date and not forced |
| 1 | nothing produced — no inputs found, or every item failed |
| 2 | config error — bad variable, missing input, unwritable output |
| 3 | partial — at least one item processed, at least one failed |

## Run

```sh
docker build -t get-sybers/godaemonhunter:latest -f godaemonhunter/Dockerfile .
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
  -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/godaemonhunter:latest gosyslog
```

(Build from the **repo root**: the image copies the sibling `pinfo/` module.)

## argv pass-through (debug only, `godaemonhunter gosyslog <args>`)

`-f FILE | -d DIR`, `-q`; records stream to stdout.
Exit 0 ok / 1 usage or fatal / 2 at least one file failed. `--version`
prints the version; `--print-contract` prints `contract.yml`.
