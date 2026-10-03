# `godaemonhunter gomachost` — macOS host identity

Part of the daemon matrix ([docs/linux](https://github.com/Get-Sybers/GoDFIR-toolz/blob/main/docs/linux/README.md)), built on
the shared [`pinfo`](https://github.com/Get-Sybers/gopinfo) module: batch runtime, record envelope,
rule-2 provenance stamping and the [`plist`](https://github.com/Get-Sybers/gopinfo/tree/main/plist) decoder come
from the module. The Mac counterpart of [`gohost`](../host/README.md) in
Layer 1: it emits the **same record types**, so the knowledge store loads a
Mac exactly as it loads a Linux host and every Layer-2 record carries the
`Host` block.

- **`os_release`** — from `System/Library/CoreServices/SystemVersion.plist`:
  `Name` (ProductName), `ID` (`macos`), `VersionID` (ProductVersion),
  `PrettyName` (`macOS 12.7.3 (21H1015)`), every key under `Fields`.
- **`hostname`** — from `Library/Preferences/SystemConfiguration/preferences.plist`:
  `Hostname` (System → System → HostName, else LocalHostName, else
  ComputerName), plus `ComputerName`, `LocalHostName` and the hardware
  `Model`.
- **`timezone`** and **`locale`** — from the system
  `Library/Preferences/.GlobalPreferences.plist` (a user's own copy under
  `Users/` is not the host's): `Timezone` is the selected city's zone name
  (`Europe/Tallinn`) with `City` and `Country`; `Lang` is AppleLocale with
  `Country` and `Languages`. (`gohost` also reads a staged
  `private/etc/localtime` symlink — its target names the zone.)

Extraction only (docs/linux §4.1): the time zone is handed over as the
name the host had selected; applying it to naive timestamps is byakugan's.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, and `Origin`/`Snapshot`/`Residue` when
a stage manifest resolves them).

As `godaemonhunter gomachost` with nothing further, the
[one binary](../README.md) runs this parser's container-framework batch
mode: it reads the `GOMACHOST_*` environment, finds every recognised
property list under the input tree, writes one output folder per file and
prints exactly one JSON summary line on stdout.

## Input

The evidence tree at `GOMACHOST_INPUT_DIR` (default `/input`), mounted
read-only — a staged Mac tree, or what `gomount materialise --set
macos-core` pulled off a disk image.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOMACHOST_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOMACHOST_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOMACHOST_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOMACHOST_WORK_DIR` | `/work` | scratch (writable tmpfs); gomachost needs none but honours it |
| `GOMACHOST_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOMACHOST_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gomachost.jsonl`, one folder per input file; `RecordType`
is `os_release`, `hostname`, `timezone` or `locale`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — every item parsed (or was already up-to-date) |
| 1 | nothing produced — none of the property lists under the input tree |
| 2 | config error — bad variable, missing input, unwritable output |
| 3 | partial — at least one item failed |

## Run

```sh
go install github.com/Get-Sybers/godaemonhunter@latest   # -> $(go env GOPATH)/bin/godaemonhunter

# env-driven — set the variables from the Env table above (point the
# *_DIR paths at local directories), then run the sub-tool:
GOMACHOST_INPUT_DIR=./in GOMACHOST_OUT_DIR=./out godaemonhunter gomachost
```

## argv pass-through (debug only)

```
godaemonhunter gomachost -f FILE | -d DIR [-q]
```
