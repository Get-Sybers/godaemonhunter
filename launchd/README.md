# `godaemonhunter golaunchd` — macOS launchd jobs and overrides

Part of the daemon matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope,
rule-2 provenance stamping and the [`plist`](../../pinfo/plist) decoder come
from the module. The Mac counterpart of [`gounit`](../unit/README.md) in the
`service` stream.

Finds every launchd property list under a `LaunchDaemons/` or
`LaunchAgents/` directory in the input tree — `/Library` (third-party, the
*library* domain), `/System/Library` (Apple's, on a System volume — the
*system* domain), `Users/<u>/Library` and `private/var/root/Library` (the
*user* domain, `Owner` the user) — and the override tables launchd keeps at
`private/var/db/com.apple.xpc.launchd/disabled.plist` (system) and
`disabled.<uid>.plist` (per user), XML or binary, and emits:

- **`launchd_job`** — one per plist (an empty `<dict/>` left behind by an
  uninstaller is one too, labelled by its file name, `Keys` empty): `Label`, `Kind` (`daemon`/`agent`),
  `Domain`, `Owner`, then the job's keys verbatim: `Program`,
  `ProgramArguments`, `RunAtLoad`, `KeepAlive` (a dictionary rendered whole
  as JSON), `Disabled`, `LaunchOnlyOnce`, `StartInterval`,
  `StartCalendarInterval` (each entry as `Minute=0 Hour=3 …`),
  `StartOnMount`, `WatchPaths`, `QueueDirectories`, `UserName`, `GroupName`,
  `WorkingDirectory`, `RootDirectory`, `EnvironmentVariables`, the standard
  I/O paths, `MachServices` and `Sockets` (their names), `ProcessType`,
  `LimitLoadToSessionType`, `AssociatedBundleIdentifiers`, `Nice`, and
  `Keys` — every top-level key the plist carries, so nothing is silently
  dropped.
- a job file that is a symlink (Apple links several System LaunchAgents
  into the cryptex under `/Library/Apple`) is recorded by its name with
  `LinkTarget`, the path its definition lives at, since the staged copy
  holds only that.
- **`launchd_override`** — one per label of a disabled table: `Label`,
  `Disabled` as launchd recorded it, `OverrideUID` for a per-user table.

Extraction only (docs/linux §4.1): the location decides kind, domain and
owner — a fact of where the file sits — and whether a job is persistence
or expected is byakugan's call. The sealed System volume's own
`/System/Library/Launch*` is only reached when that volume is staged
(a second volume pass; the Data volume does not hold it).

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, and `Origin`/`Snapshot`/`Residue` when
a stage manifest resolves them, `Host` from the knowledge store).

As `godaemonhunter golaunchd` with nothing further, the
[one binary](../README.md) runs this parser's container-framework batch
mode: it reads the `GOLAUNCHD_*` environment, finds every launchd plist
under the input tree, writes one output folder per file and prints exactly
one JSON summary line on stdout.

## Input

The evidence tree at `GOLAUNCHD_INPUT_DIR` (default `/input`), mounted
read-only — a staged Mac tree, or what `gomount materialise --set
macos-core` pulled off a disk image. A `materialise.jsonl` manifest at the
input root, when present, is joined onto every record.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOLAUNCHD_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOLAUNCHD_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOLAUNCHD_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOLAUNCHD_WORK_DIR` | `/work` | scratch (writable tmpfs); golaunchd needs none but honours it |
| `GOLAUNCHD_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOLAUNCHD_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/golaunchd.jsonl`, one folder per input file; `RecordType`
is `launchd_job` or `launchd_override`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — every item parsed (or was already up-to-date) |
| 1 | nothing produced — no launchd plist under the input tree |
| 2 | config error — bad variable, missing input, unwritable output |
| 3 | partial — at least one item failed (a plist that is not a job) |

## Run

```sh
go install github.com/get-sybers/godaemonhunter@latest   # -> $(go env GOPATH)/bin/godaemonhunter

# env-driven — set the variables from the Env table above (point the
# *_DIR paths at local directories), then run the sub-tool:
GOLAUNCHD_INPUT_DIR=./in GOLAUNCHD_OUT_DIR=./out godaemonhunter golaunchd
```

## argv pass-through (debug only)

```
godaemonhunter golaunchd -f FILE | -d DIR [-q]
```

Records go to stdout; kind, domain and owner come from the path given.
