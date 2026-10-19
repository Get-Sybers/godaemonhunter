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
([`model/car/objects`](https://github.com/Get-Sybers/Byakugan/-/tree/main/model/car/objects)
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
| `file` | gotrash, gofsevents |
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
| [`gofsevents`](fsevents/README.md) | macOS fseventsd `/.fseventsd/` filesystem-change logs (DLS), one record per change |

**A Mac is the same run.** Point it at a macOS disk image (APFS or HFS+ —
gomount resolves the Data volume) or a staged Mac tree and the layered
pipeline is unchanged: gomachost and gomacusers build the knowledge store
from the property lists, golaunchd feeds the `service` stream beside
gounit, gofsevents reads the `/.fseventsd/` change log for the `file`
stream, and the Linux parsers read the macOS shapes of their own
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
the stage, never from the parser. Beside the image, volume, `FSUUID`/`Label`,
original path and inode, `Origin` carries the evidence-asset identity
[gomount](../gomount) ≥ v0.4.0 records on the manifest: the drive/device
serial (`DiskSerial`) and disk GUID or MBR signature (`DiskID`), and the
volume's `VolumeGUID`, `PartGUID` and `PartOffset` — each `omitempty`, stamped
only where the image format and partitioning provide them (so a resolver
downstream can key each row to one evidence asset). The host's own machine id
rides `Host.MachineID`, and `ImageSHA256` carries the acquisition bytes'
sha256 — the hunt pulls the image with gomount's `materialise --hash`, one
extra sequential read of the container, paid once on the primary pull.

Two more kinds of host sit *beside* the loose tree and are hunted **on**
(see below): the disk images directly under the input root
(`GODAEMONHUNTER_IMAGE` names one), and the **UAC collections** — the
`uac-<hostname>-<os>-<timestamp>.tar.gz`, `.tar` or `.zip` archives the
[Unix-like Artifacts Collector](https://github.com/tclahr/uac) writes.

## UAC collections

A UAC collection holds the host's files under `[root]/` with their paths
intact (`[root]/etc/passwd`, `[root]/var/log/auth.log`, …) and the
collector's own output beside them (`uac.log`, `bodyfile/`,
`hash_executables/`, `live_response/`, …). The baked-in gomount reads the
archive as an image: `gomount identify` names it (a `collection` block
from `uac.log` and a volume of fstype `uac`, the `[root]` tree, with the
collector's output as a second volume), and `gomount materialise --set
linux-core` pulls the daemon parsers' surface out of `[root]/` exactly as
off an ext4 root — so a collection is simply another image item.
`GODAEMONHUNTER_IMAGE` may name one; without `IMAGE`, every archive
directly under the input root that identify confirms as a collection is
hunted beside the disk images (a zip or tar of anything else is reported
and skipped; UAC's `uac-<…>.log` acquisition-log sidecar is never an item).
The knowledge store lands at `<KNOWLEDGE_DIR>/<archive>/`, the records under
`<OUT_DIR>/<subtool>/<archive>/`, every record's `Origin` naming the archive
and the `[root]` volume; the summary line lists the archives under
`collections` (and, as hosts, under `images`). A gzip'd collection is
spooled once while gomount reads it, under the work dir (`TMPDIR` is set to
it for the gomount run), so bind a disk-backed `/work` for a large one.

Only the host's files are read today. The `live_response/` snapshot a
live-host collection also carries (ps, netstat/ss, systemctl, lsmod, who)
is tracked as
[godaemonhunter#8](https://github.com/Get-Sybers/godaemonhunter/issues/8),
and the collection's `bodyfile/bodyfile.txt` as a full fs:stat timeline as
[gomount#9](https://github.com/Get-Sybers/gomount/issues/9). Note that
UAC's zip output dereferences symlinks (Info-ZIP without `-y`), so a zip
collection lacks the `*.wants/` enablement links a tar collection keeps;
prefer `--output-format tar` where you can choose.

## Env (the layered run)

| Variable | Default | Meaning |
|---|---|---|
| `GODAEMONHUNTER_INPUT_DIR` | `/input` | evidence tree, recursed read-only, shared by every sub-run |
| `GODAEMONHUNTER_OUT_DIR` | `/output` | output root: `knowledge/` (Layer 1) + one `<subtool>/` tree per daemon parser |
| `GODAEMONHUNTER_KNOWLEDGE_DIR` | *(empty)* | override the knowledge store location; empty = `<OUT_DIR>/knowledge`, built by Layer 1 in the same run |
| `GODAEMONHUNTER_WORK_DIR` | `/work` | scratch (writable tmpfs), shared by every sub-run; a disk image's linux-core surface is pulled here while its parsers run — bind a disk-backed directory for large images |
| `GODAEMONHUNTER_IMAGE` | *(empty)* | run **on a disk image or a UAC collection**: its path relative to `INPUT_DIR` (E01/Ex01, raw, VMDK, VHDX, VHD, QCOW2, VDI, DMG (.dmg), sparseimage (.sparseimage); or the `.tar.gz`/`.tar`/`.zip` the Unix-like Artifacts Collector writes, whose `[root]/` tree is the root volume). The baked-in [gomount](../gomount) pulls the `linux-core` surface out of the root volume into `WORK_DIR`, the layered run goes over that as over a staged root tree, the knowledge store lands at `<KNOWLEDGE_DIR>/<image>/` and the records under `<OUT_DIR>/<subtool>/<image>/…`, the scratch goes — nothing is exported. Empty = the loose tree itself plus every image directly under it plus every archive there that `gomount identify` confirms as a collection. A sub-tool run reads `<SUBTOOL>_IMAGE` and writes `<OUT_DIR>/<image>/…` |
| `GODAEMONHUNTER_LIVE` | `0` | run **on the live host** (see [Running on a live system](#running-on-a-live-system)): `1/true/yes/on` stages the known artefact surface of the live root and runs the layered pipeline over it. Mutually exclusive with `GODAEMONHUNTER_IMAGE`; `INPUT_DIR` is unused |
| `GODAEMONHUNTER_LIVE_ROOT` | `/` | the live root `LIVE` collects from — a read-only bind-mount of the host filesystem (a live-response container) or a staged root tree |
| `GODAEMONHUNTER_LIVE_OS` | *(this host's OS)* | the live-collection profile: `linux` or `darwin` ([`livecollect/profiles.json`](livecollect/profiles.json)) |
| `GODAEMONHUNTER_LIVE_MAX_FILE` | `0` | per-file byte cap on the live collection; `0` = no cap — bind a disk-backed work dir for a large collection |
| `GODAEMONHUNTER_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output, in every sub-run |
| `GODAEMONHUNTER_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only, applied to every sub-run |

A single-parser sub-run (`godaemonhunter gowtmp`) ignores the
`GODAEMONHUNTER_*` block and reads that tool's canonical `<SUBTOOL>_*`
variables instead (`GOWTMP_INPUT_DIR`, `GOWTMP_OUT_DIR`, …) — each
parser package's README documents its block.

## Running on a live system

A disk image is a host, and so is the machine the binary is running on.
Set `GODAEMONHUNTER_LIVE=1` (mutually exclusive with
`GODAEMONHUNTER_IMAGE`) and the baked-in
[`livecollect`](livecollect/README.md) copies the known artefact surface
out of the live root into the work dir — **only** the known trees, never
`/proc`, `/sys` or other mounts, and a per-file read failure is logged and
skipped rather than fatal — then the same layered run goes over that
snapshot. The knowledge store lands at `<KNOWLEDGE_DIR>/<host>/` and the
records under `<OUT_DIR>/<subtool>/<host>/`, the host folder named for the
live host; the scratch goes, nothing is exported. Each record's
`Origin.Path` is its real on-host path and it carries no `Snapshot` — the
live volume.

Why not point `INPUT_DIR` at `/` instead: every parser discovers its files
by recursing the whole input root, and that walk fails the run on the first
unreadable directory. A live `/` would descend `/proc`, `/sys` and every
mounted filesystem and die at once. Staging only the known surface sidesteps
that and captures a point-in-time snapshot of volatile logs — the
forensically correct behaviour for a running host.

```sh
# collect and parse the running host — run as root for the full surface
# (shadow, audit, the journal, every user's home)
GODAEMONHUNTER_LIVE=1 GODAEMONHUNTER_OUT_DIR=./out godaemonhunter

# from a container with the host filesystem bind-mounted read-only at /host
GODAEMONHUNTER_LIVE=1 GODAEMONHUNTER_LIVE_ROOT=/host GODAEMONHUNTER_OUT_DIR=./out godaemonhunter

# one parser, live
GOSYSLOG_LIVE=1 GOSYSLOG_OUT_DIR=./out godaemonhunter gosyslog
```

**macOS is the same live run.** On a Mac the `darwin` profile collects the
property lists, the launchd jobs and disabled-overrides tables, the
OpenDirectory dslocal node, the ASL-fed system logs, utmpx, the periodic and
at jobs and the per-session histories — and because the live `/` already
merges the System and Data volumes there is no two-volume step the image path
needs. Not yet read, as for an image: the unified log (`tracev3`), ASL
stores, BTM login items, the TCC/KnowledgeC/quarantine databases and
fseventsd.

The exact set each profile collects is data —
[`livecollect/profiles.json`](livecollect/profiles.json) — so tuning a path
or adding an OS is a data change.

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
go install github.com/Get-Sybers/godaemonhunter@latest   # -> $(go env GOPATH)/bin/godaemonhunter

# every stream (the default layered run), env-driven — see Env (the layered
# run) above; point the *_DIR paths at local directories:
GODAEMONHUNTER_INPUT_DIR=./in GODAEMONHUNTER_OUT_DIR=./out godaemonhunter
```

Or scope to a single sub-tool's env-driven batch — each reads its own
`<SUBTOOL>_*` block (see the per-parser READMEs):

```sh
GOCRON_INPUT_DIR=./in GOCRON_OUT_DIR=./out godaemonhunter gocron
```

The shared runtime is imported from the published
[`github.com/Get-Sybers/gopinfo`](https://github.com/Get-Sybers/gopinfo) module,
not vendored here. Container images are built and documented separately in
[GoDFIR-toolz](https://github.com/Get-Sybers/GoDFIR-toolz).

## argv pass-through (debug only)

`godaemonhunter <subtool> <args>` hands the rest of the command line to
that parser's own argv debug mode: `-f FILE | -d DIR | --tar` (a
`gomount stream` tar on stdin), `-q`; records stream to stdout — see each
package README for its exact flags. `--version` prints the version;
`--print-contract` prints [`contract.yml`](contract.yml).
