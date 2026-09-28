# `godaemonhunter gomacusers` — macOS local accounts

Part of the daemon matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope,
rule-2 provenance stamping and the [`plist`](../../pinfo/plist) decoder come
from the module. The Mac counterpart of [`gousers`](../users/README.md) in
Layer 1: it emits the **same `account` and `group` record types**, so the
knowledge store resolves a Mac's uids and gids exactly as a Linux host's
(`gousers` itself still reads the Mac's `private/etc/passwd`,
`master.passwd`, `group` and `sudoers`).

Reads the OpenDirectory local node — one property list per record under
`private/var/db/dslocal/nodes/Default/users/` and `groups/`, XML or binary
— and emits:

- **`account`** — `Username` (the first `name`, the rest as `Aliases`),
  `UID`, `GID`, `GECOS` (realname), `HomeDir`, `Shell`, `GeneratedUID`,
  `SMBSID`, `AuthenticationAuthority` (the `;ShadowHash;…`,
  `;Kerberosv5;…`, `;SecureToken;` strings verbatim), `HasShadowHash`
  (the hash blob is reported present, never carried), `IsHidden`,
  `Picture`, and from the account-policy blob (a plist inside a data
  attribute) `AccountCreated`, `PasswordLastSet` — also the record's
  `EventTime` with `TimeKind` `password_change` — `FailedLoginCount` and
  `FailedLoginTime`; `Keys` lists every attribute the record carries.
- **`group`** — `GroupName` (+ `Aliases`), `GID`, `GECOS`, `Members`
  (`users`), `GroupMembers` (the member GUIDs), `GeneratedUID`, `SMBSID`.

Extraction only (docs/linux §4.1): native values verbatim, nothing judged.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, `EventTime` UTC, `TimeKind`, and
`Origin`/`Snapshot`/`Residue` when a stage manifest resolves them).

As `godaemonhunter gomacusers` with nothing further, the
[one binary](../README.md) runs this parser's container-framework batch
mode: it reads the `GOMACUSERS_*` environment, finds every dslocal record
under the input tree, writes one output folder per file and prints exactly
one JSON summary line on stdout.

## Input

The evidence tree at `GOMACUSERS_INPUT_DIR` (default `/input`), mounted
read-only — a staged Mac tree, or what `gomount materialise --set
macos-core` pulled off a disk image.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOMACUSERS_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOMACUSERS_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOMACUSERS_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOMACUSERS_WORK_DIR` | `/work` | scratch (writable tmpfs); gomacusers needs none but honours it |
| `GOMACUSERS_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOMACUSERS_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gomacusers.jsonl`, one folder per input file; `RecordType`
is `account` or `group`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — every item parsed (or was already up-to-date) |
| 1 | nothing produced — no dslocal record under the input tree |
| 2 | config error — bad variable, missing input, unwritable output |
| 3 | partial — at least one item failed |

## Run

```sh
go install github.com/get-sybers/godaemonhunter@latest   # -> $(go env GOPATH)/bin/godaemonhunter

# env-driven — set the variables from the Env table above (point the
# *_DIR paths at local directories), then run the sub-tool:
GOMACUSERS_INPUT_DIR=./in GOMACUSERS_OUT_DIR=./out godaemonhunter gomacusers
```

## argv pass-through (debug only)

```
godaemonhunter gomacusers -f FILE | -d DIR [-q]
```
