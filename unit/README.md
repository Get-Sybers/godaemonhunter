# `godaemonhunter gounit` — systemd units and timers

Part of the Linux matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope and
rule-2 provenance stamping come from the module, not a copied `batch.go`.

Finds unit files (`.service`, `.timer`, `.socket`, `.mount`,
`.automount`, `.path`, `.target`, `.slice`, `.swap`) and their
drop-in fragments (`<unit>.d/*.conf`) across `etc/`, `run/`,
`usr/lib|lib/` and per-user systemd directories. One record per file:
every `Exec*` line in order (empty-assignment reset honoured), `User`,
timer schedule verbatim, `[Install]` targets as declared, Condition/Assert
lines, and `Scope` — where the file sat (vendor/admin/runtime/user), a
location fact that makes an `/etc` override of a vendor unit stand out.
Enablement symlinks (`*.wants/`) are filesystem structure: the access
layer's timeline records them, this parser reads regular files only.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, `EventTime` UTC, `TimeKind`, and
`Origin`/`Snapshot`/`Residue` when a stage manifest resolves them). The
declared record fields are in [`contract.yml`](../contract.yml).

As `godaemonhunter gounit` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode: it
reads the `GOUNIT_*` environment, finds every artefact it handles under the
input tree, writes one output folder per file and prints exactly one JSON
summary line on stdout.

## Input

The evidence tree at `GOUNIT_INPUT_DIR` (default `/input`), mounted
read-only: a staged `linux-core` materialise tree or any loose collection.
A `materialise.jsonl` manifest at the input root, when present, is joined
onto every record as `Origin`/`Snapshot`/`Residue`.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOUNIT_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOUNIT_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOUNIT_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOUNIT_WORK_DIR` | `/work` | scratch (writable tmpfs); gounit needs none but honours it |
| `GOUNIT_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOUNIT_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gounit.jsonl`, one folder per unit file;
`RecordType` is `systemd_unit` or `systemd_dropin`.

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
  get-sybers/godaemonhunter:latest gounit
```

(Build from the **repo root**: the image copies the sibling `pinfo/` module.)

## argv pass-through (debug only, `godaemonhunter gounit <args>`)

`-f FILE | -d DIR`, `-q`; records stream to stdout.
Exit 0 ok / 1 usage or fatal / 2 at least one file failed. `--version`
prints the version; `--print-contract` prints `contract.yml`.
