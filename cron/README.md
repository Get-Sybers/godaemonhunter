# `godaemonhunter gocron` — Linux scheduled tasks (cron, anacron, at)

Part of the Linux matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope and
rule-2 provenance stamping come from the module, not a copied `batch.go`.

Finds `etc/crontab`, `cron.d/` fragments, run-parts membership
(`cron.hourly` … `cron.monthly`), user spool crontabs (Debian
`crontabs/<user>` and RH `cron/<user>` layouts), `anacrontab` and at
spool jobs. Schedules are recorded verbatim (five-field and `@keyword`
forms); the user column only where the format carries one — a spool file's
owner is its filename, recorded as `SpoolOwner`. At jobs capture the
`# atrun uid= gid=` header and the script body to 64KiB. Next-run
resolution is derivation and stays byakugan-side.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, `EventTime` UTC, `TimeKind`, and
`Origin`/`Snapshot`/`Residue` when a stage manifest resolves them). The
declared record fields are in [`contract.yml`](../contract.yml).

As `godaemonhunter gocron` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode: it
reads the `GOCRON_*` environment, finds every artefact it handles under the
input tree, writes one output folder per file and prints exactly one JSON
summary line on stdout.

## Input

The evidence tree at `GOCRON_INPUT_DIR` (default `/input`), mounted
read-only: a staged `linux-core` materialise tree or any loose collection.
A `materialise.jsonl` manifest at the input root, when present, is joined
onto every record as `Origin`/`Snapshot`/`Residue`.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOCRON_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOCRON_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOCRON_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOCRON_WORK_DIR` | `/work` | scratch (writable tmpfs); gocron needs none but honours it |
| `GOCRON_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOCRON_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gocron.jsonl`, one folder per input file;
`RecordType` is `crontab_entry`, `crontab_env`, `anacrontab_entry`,
`at_job` or `cron_runparts`.

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
  get-sybers/godaemonhunter:latest gocron
```

(Build from the **repo root**: the image copies the sibling `pinfo/` module.)

## argv pass-through (debug only, `godaemonhunter gocron <args>`)

`-f FILE | -d DIR`, `-q`; records stream to stdout.
Exit 0 ok / 1 usage or fatal / 2 at least one file failed. `--version`
prints the version; `--print-contract` prints `contract.yml`.
