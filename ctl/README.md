# `godaemonhunter goctl` — the kernel and loader control surface

Part of the Linux matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope and
rule-2 provenance stamping come from the module, not a copied `batch.go`.

Parses the persisted knobs that change how the kernel and the dynamic
loader behave — a classic persistence and anti-forensics surface — with
the `Scope` (vendor `usr/lib` / admin `etc` / runtime `run`) that
makes an admin override of a vendor default stand out:

- **sysctl** — `sysctl.conf` and every `sysctl.d/*.conf`: one
  `sysctl_param` per line (`net.ipv4.ip_forward`,
  `kernel.yama.ptrace_scope`, …), the error-ignoring `-` prefix kept in
  `Raw`.
- **module policy** — `modules-load.d/*.conf` and `etc/modules`
  (`module_load`), and `modprobe.d/*.conf` (`modprobe_directive`):
  `blacklist` hides modules, `options` changes them, and
  `install`/`remove` values are shell commands the kernel module
  machinery executes — recorded verbatim.
- **the dynamic loader** — `etc/ld.so.preload` (`ld_preload`, one
  record per library: THE preload persistence artefact) and
  `ld.so.conf` + `ld.so.conf.d` (`ld_path` search paths and
  includes).

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, `EventTime` — ISO 8601 UTC at fixed
microsecond precision — `TimeKind`, and `Origin`/`Snapshot`/`Residue`
when a stage manifest resolves them). The declared record fields are in
[`contract.yml`](../contract.yml).

As `godaemonhunter goctl` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode: it
reads the `GOCTL_*` environment, finds every artefact it handles under the
input tree, writes one output folder per file and prints exactly one JSON
summary line on stdout.

## Input

The evidence tree at `GOCTL_INPUT_DIR` (default `/input`), mounted
read-only. A `materialise.jsonl` manifest at the input root, when present,
is joined onto every record as `Origin`/`Snapshot`/`Residue`.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GOCTL_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GOCTL_OUT_DIR` | `/output` | output root, one folder per input file |
| `GOCTL_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GOCTL_WORK_DIR` | `/work` | scratch (writable tmpfs); goctl needs none but honours it |
| `GOCTL_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GOCTL_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/goctl.jsonl`; `RecordType` is `sysctl_param`,
`module_load`, `modprobe_directive`, `ld_preload` or `ld_path`.

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
  get-sybers/godaemonhunter:latest goctl
```

(Build from the **repo root**: the image copies the sibling `pinfo/` module.)

## argv pass-through (debug only, `godaemonhunter goctl <args>`)

`-f FILE | -d DIR`, `-q`; records stream to stdout. Exit 0 ok / 1 usage
or fatal / 2 at least one file failed. `--version` prints the version;
`--print-contract` prints `contract.yml`.
