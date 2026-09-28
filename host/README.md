# `godaemonhunter gohost` — host identity and storage mapping

Part of the Linux matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope and
rule-2 provenance stamping come from the module, not a copied `batch.go`.

Extracts the facts that anchor every other record:

- **Who the host is** — `etc/os-release` (Name/ID/VersionID/PrettyName +
  every other key), `etc/hostname`, `etc/machine-id` (32-hex, joins
  gojournal's `MachineID`), `etc/timezone` and a staged `etc/localtime`
  (the TZif v2+ trailing POSIX rule; the symlink's zone *name* is lost in
  staging and honestly absent), `locale.conf`/`default/locale`.
- **How volumes map to names** — the role a drive serial plays on Windows:
  `etc/fstab` rows tie a durable volume identity (`UUID=`, `LABEL=`,
  `PARTUUID=`, `/dev/disk/by-uuid/…`, split into `SpecType` + `UUID`/
  `Label`) to its `MountPoint`, type and options; `etc/crypttab` rows tie
  an encrypted backing device to its `MapperName` and key source.

Extraction only (docs/linux §4.1, the rules): *applying* the timezone to
naive log timestamps, and *joining* a UUID to a volume (`Origin.FSUUID`
from the access layer's manifest) or to a mapper name, is byakugan's.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, `EventTime` UTC, `TimeKind`, and
`Origin`/`Snapshot`/`Residue` when a stage manifest resolves them). The
declared record fields are in [`contract.yml`](../contract.yml).

As `godaemonhunter gohost` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode: it
reads the `GOHOST_*` environment, finds every recognised host-config file
under the input tree, writes one output folder per file and prints exactly
one JSON summary line on stdout.

## Input

The evidence tree at `GOHOST_INPUT_DIR` (default `/input`), mounted
read-only. A `materialise.jsonl` manifest at the input root, when present,
is joined onto every record as `Origin`/`Snapshot`/`Residue`.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOHOST_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOHOST_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOHOST_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOHOST_WORK_DIR` | `/work` | scratch (writable tmpfs); gohost needs none but honours it |
| `GOHOST_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOHOST_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gohost.jsonl`, one folder per input file; `RecordType`
is `os_release`, `hostname`, `machine_id`, `timezone`, `locale`,
`fstab_entry` or `crypttab_entry`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — work done, or already up-to-date and not forced |
| 1 | nothing produced — no host-config files found, or every item failed |
| 2 | config error — bad variable, missing input, unwritable output |
| 3 | partial — at least one item processed, at least one failed |

## Run

```sh
docker build -t get-sybers/godaemonhunter:latest -f godaemonhunter/Dockerfile .
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
  -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/godaemonhunter:latest gohost
```

(Build from the **repo root**: the image copies the sibling `pinfo/` module.)

## argv pass-through (debug only, `godaemonhunter gohost <args>`)

`-f FILE | -d DIR`, `-q`; records stream to stdout. Exit 0 ok / 1 usage or
fatal / 2 at least one file failed. `--version` prints the version;
`--print-contract` prints `contract.yml`.
