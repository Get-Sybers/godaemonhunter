# `get-sybers/godaemonhunter` — the Linux matrix as one structured binary

Every daemon parser of the Linux matrix (the Linux design, decisions
15–17) is a package of this module and a sub-tool of this single
static binary, run through the layered one-shot:

1. **Layer 1** runs first — `gohost`, `gousers`, `gonetwork` — and their
   output *is* the image's knowledge store (identity, naming, layout:
   uid/gid→name, hostname, machine-id, timezone, mounts).
2. **Layer 2** — `gojournal`, `goauditd`, `gowtmp`, `gosyslog`, `gounit`,
   `gocron`, `goshell`, `gotrash`, `goctl` — then runs with that store
   mounted, so every record comes out enriched per decision 14: resolved
   names **beside** the native values (`UIDName` next to `UID`, never
   replacing it), the `Host` block stamped, naive syslog timestamps placed
   in the image's own zone. Correlation and joining stay byakugan's job.

One binary, one run, one structured output tree, one JSON summary line.
This is the multi-tool self-orchestration shape defined by the get-sybers
framework standard (the plaso and signatures precedent) — and per decision 16
it is the
**only** shipped shape: the parsers live here as packages, and there are
no standalone per-parser binaries or images. godaemonhunter *is* the
Linux tool.

## The stream is the parameter

The binary is called with a **stream**: a word that is a byakugan model
([`model/car/objects`](https://github.com/Get-Sybers/Byakugan/tree/main/model/car/objects)
at the `BYAKUGAN_REF` pin). A stream scopes the layered run to the daemon
parsers whose records feed that model's maps; **the default — no
arguments — is every stream**. Layer 1 is never scoped: it is the
knowledge store.

```
godaemonhunter                     every stream (the default layered run)
godaemonhunter <stream>...         scope it to one or more streams
godaemonhunter <subtool>           one parser's env-driven batch mode, under
                                   its canonical <SUBTOOL>_* block
godaemonhunter <subtool> <args>    that parser's argv debug pass-through
godaemonhunter --version | --print-contract
```

| Stream (= byakugan model) | Runs |
|---|---|
| `authentication` | gojournal, gosyslog, gowtmp, goauditd |
| `user_session` | gowtmp, gojournal, gosyslog, goauditd |
| `process` | goauditd, goshell, gojournal, gosyslog |
| `service` | gounit, golaunchd, gocron, gojournal, gosyslog |
| `flow` | goauditd |
| `file` | gotrash |
| `module` | goctl |

Model words nothing here feeds yet (`registry`, `thread`, …) are rejected
with the accepted list. `hunt` stays accepted as the explicit word for
the default run. The aggregate summary line names the streams it ran
under `streams`.

Sub-tools — each one a package of this module with its own README
documenting what it parses, its `<SUBTOOL>_*` env block and its record
shapes:

| Layer 1 — the knowledge builders | |
|---|---|
| [`gohost`](host/README.md) | host identity (os-release, hostname, machine-id, timezone, locale) + fstab/crypttab volume mapping |
| [`gousers`](users/README.md) | passwd/shadow/group, sudoers, SSH access surface |
| [`gonetwork`](network/README.md) | hosts, resolv, nsswitch, TCP wrappers, interface/connection profiles, firewall state |
| [`gomachost`](machost/README.md) | macOS: SystemVersion.plist, the SystemConfiguration host names and model, the system time zone and locale — the same `os_release`/`hostname`/`timezone`/`locale` rows |
| [`gomacusers`](macusers/README.md) | macOS: the OpenDirectory local node (dslocal users and groups) — the same `account`/`group` rows |

| Layer 2 — the daemon parsers | |
|---|---|
| [`gojournal`](journal/README.md) | systemd journal `*.journal` files, typed families |
| [`goauditd`](auditd/README.md) | audit.log records coalesced into events |
| [`gowtmp`](wtmp/README.md) | utmp/wtmp/btmp login records + lastlog |
| [`gosyslog`](syslog/README.md) | syslog-family text logs, typed families |
| [`gounit`](unit/README.md) | systemd units, timers, drop-ins |
| [`gocron`](cron/README.md) | crontabs, cron.d, anacron, at |
| [`goshell`](shell/README.md) | shell/REPL histories |
| [`gotrash`](trash/README.md) | XDG Trash |
| [`goctl`](ctl/README.md) | sysctl, module policy, ld.so preload/conf |
| [`golaunchd`](launchd/README.md) | macOS launchd jobs (LaunchDaemons/LaunchAgents in every domain) and the disabled-overrides tables |

**A Mac is the same run.** Point it at a macOS disk image (APFS or HFS+ —
gomount resolves the Data volume) or a staged Mac tree and the layered
pipeline is unchanged: gomachost and gomacusers build the knowledge store
from the property lists, golaunchd feeds the `service` stream beside
gounit, and the Linux parsers read the macOS shapes of their own
artefacts — gosyslog `system.log`/`install.log`/`wifi.log` (bzip2
rotations included), gowtmp the 628-byte `utmpx`, gocron `var/at/tabs`,
`var/at/jobs` and the `etc/periodic` scripts, goshell the per-session
`.bash_sessions`/`.zsh_sessions` histories, gousers `master.passwd` and
`sudoers`, gohost a staged `localtime` symlink's zone name. The image pull
asks gomount for both `linux-core` and `macos-core`; the OS volume holds
one of them — and when `gomount identify` shows a Data volume beside a
System volume (macOS 10.15+), a second pass pulls `macos-system` off the
System volume (SystemVersion.plist, Apple's own LaunchDaemons and
LaunchAgents) into the same staged tree, each file's manifest row naming
its volume. Not yet read: the unified log (`tracev3`), ASL stores, BTM
login items, the TCC/KnowledgeC/quarantine databases and fseventsd.

## Input

The evidence tree at `GODAEMONHUNTER_INPUT_DIR` (default `/input`), mounted
read-only and shared by every sub-run: a staged `linux-core` materialise
tree, a mounted root filesystem, or any directory laid out like one. A
`materialise.jsonl` manifest at the input root, when present, is joined onto
every record as `Origin`/`Snapshot`/`Residue` — rule-2 provenance comes from
the stage, never from the parser.

## Env (the layered run)

| Variable | Default | Meaning |
|---|---|---|
| `GODAEMONHUNTER_INPUT_DIR` | `/input` | evidence tree, recursed read-only, shared by every sub-run |
| `GODAEMONHUNTER_OUT_DIR` | `/output` | output root: `knowledge/` (Layer 1) + one `<subtool>/` tree per daemon parser |
| `GODAEMONHUNTER_KNOWLEDGE_DIR` | *(empty)* | override the knowledge store location; empty = `<OUT_DIR>/knowledge`, built by Layer 1 in the same run |
| `GODAEMONHUNTER_WORK_DIR` | `/work` | scratch (writable tmpfs), shared by every sub-run; a disk image's linux-core surface is pulled here while its parsers run — bind a disk-backed directory for large images |
| `GODAEMONHUNTER_IMAGE` | *(empty)* | run **on a disk image**: its path relative to `INPUT_DIR` (E01/Ex01, raw, VMDK, VHDX, VHD, QCOW2, VDI, DMG (.dmg), sparseimage (.sparseimage)). The baked-in [gomount](../gomount) pulls the `linux-core` surface out of the root volume into `WORK_DIR`, the layered run goes over that as over a staged root tree, the knowledge store lands at `<KNOWLEDGE_DIR>/<image>/` and the records under `<OUT_DIR>/<subtool>/<image>/…`, the scratch goes — nothing is exported. Empty = the loose tree itself plus every image directly under it. A sub-tool run reads `<SUBTOOL>_IMAGE` and writes `<OUT_DIR>/<image>/…` |
| `GODAEMONHUNTER_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output, in every sub-run |
| `GODAEMONHUNTER_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only, applied to every sub-run |

A single-parser sub-run (`godaemonhunter gowtmp`) ignores the
`GODAEMONHUNTER_*` block and reads that tool's canonical `<SUBTOOL>_*`
variables instead (`GOWTMP_INPUT_DIR`, `GOWTMP_OUT_DIR`, …) — each
parser package's README documents its block.

## Output

The layered run (bare or stream-scoped) writes one structured tree under
`GODAEMONHUNTER_OUT_DIR`:

```
<OUT_DIR>/knowledge/<item>/{gohost,gousers,gonetwork,gomachost,gomacusers}.jsonl   Layer 1 = the store
<OUT_DIR>/<subtool>/<item>/<subtool>.jsonl                    per selected daemon parser, enriched
```

and prints **one** aggregate JSON summary line with the stream words it
ran under `streams` and every sub-tool's own summary embedded under
`subtools` (plus `knowledge_dir`, the roll-up counters, `status`,
`exit`). A single-parser sub-run prints that parser's ordinary summary
line and writes as its own README declares.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success — every sub-run succeeded (or was already up-to-date) |
| 1 | nothing produced — no sub-run found anything to parse |
| 2 | config error — any sub-run hit a bad variable / missing input / unwritable output |
| 3 | partial — work was produced but at least one item or sub-run failed |

Roll-up order: any config error → 2; else any partial → 3; else any work → 0;
else 1.

## Run

```sh
docker build -t get-sybers/godaemonhunter:latest -f godaemonhunter/Dockerfile .
docker run --rm --cap-drop ALL --security-opt no-new-privileges --network none \
  --read-only --tmpfs /work:rw,nosuid,nodev,uid=2000,gid=2000 \
  -v "$PWD/in:/input:ro" -v "$PWD/out:/output" \
  get-sybers/godaemonhunter:latest              # every stream (the default)
```

Scoped, the stream is the only thing that changes:

```sh
docker run --rm … get-sybers/godaemonhunter:latest authentication
```

(Build from the **repo root**: the image copies the sibling `pinfo/`
module; the parser packages already live in this directory.)

## argv pass-through (debug only)

`godaemonhunter <subtool> <args>` hands the rest of the command line to
that parser's own argv debug mode: `-f FILE | -d DIR | --tar` (a
`gomount stream` tar on stdin), `-q`; records stream to stdout — see each
package README for its exact flags. `--version` prints the version;
`--print-contract` prints [`contract.yml`](contract.yml).
