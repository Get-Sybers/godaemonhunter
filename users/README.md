# `godaemonhunter gousers` — Linux accounts and access surface

Part of the Linux matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope and
rule-2 provenance stamping come from the module, not a copied `batch.go`.

Finds `passwd`, `shadow`, `group`, `gshadow` (their `-` backups too),
`sudoers` with `sudoers.d/`, `sshd_config` with drop-ins,
`authorized_keys` and `known_hosts` under the input tree and emits typed
records per line: accounts (uid 0 is a real value), shadow ageing
(day-counts native, also rendered as dates — `EventTime` is the password
change, TimeKind `password_change`), groups and their members, sudoers
defaults/aliases/rules (tags like `NOPASSWD` split out, `Raw` always
kept), sshd directives with their `Match` context, and SSH keys identified
by the standard OpenSSH SHA256 fingerprint. Crypt strings, NIS entries and
hashed known_hosts patterns are recorded verbatim — judging them is
byakugan's.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, `EventTime` UTC, `TimeKind`, and
`Origin`/`Snapshot`/`Residue` when a stage manifest resolves them). The
declared record fields are in [`contract.yml`](../contract.yml).

As `godaemonhunter gousers` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode: it
reads the `GOUSERS_*` environment, finds every artefact it handles under the
input tree, writes one output folder per file and prints exactly one JSON
summary line on stdout.

## Input

The evidence tree at `GOUSERS_INPUT_DIR` (default `/input`), mounted
read-only: a staged `linux-core` materialise tree or any loose collection.
A `materialise.jsonl` manifest at the input root, when present, is joined
onto every record as `Origin`/`Snapshot`/`Residue`.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOUSERS_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOUSERS_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOUSERS_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOUSERS_WORK_DIR` | `/work` | scratch (writable tmpfs); gousers needs none but honours it |
| `GOUSERS_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOUSERS_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gousers.jsonl`, one folder per input file;
one record per meaningful line, `RecordType` per family (`account`,
`shadow`, `group`, `gshadow`, `sudoers_*`, `sshd_config`,
`authorized_key`, `known_host`).

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
  get-sybers/godaemonhunter:latest gousers
```

(Build from the **repo root**: the image copies the sibling `pinfo/` module.)

## argv pass-through (debug only, `godaemonhunter gousers <args>`)

`-f FILE | -d DIR`, `-q`; records stream to stdout.
Exit 0 ok / 1 usage or fatal / 2 at least one file failed. `--version`
prints the version; `--print-contract` prints `contract.yml`.
