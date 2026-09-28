# `godaemonhunter gonetwork` — the network configuration surface

Part of the Linux matrix ([docs/linux](../../docs/linux/README.md)), built on
the shared [`pinfo`](../../pinfo) module: batch runtime, record envelope and
rule-2 provenance stamping come from the module, not a copied `batch.go`.

Parses the image's network posture as typed records, values verbatim:
name resolution (`etc/hosts` entries, `resolv.conf` directives,
`nsswitch.conf` databases), TCP wrappers (`hosts.allow`/`hosts.deny`
rules with their option field), interface and connection profiles —
ifupdown `interfaces` stanzas (+`interfaces.d`), systemd-networkd
`.network`/`.netdev`/`.link` files, NetworkManager
`system-connections/*.nmconnection` (id, type, uuid, SSID lifted; every
other key kept verbatim, security material included — the shadow-crypt
rule: evidence is extracted, judging it is byakugan's) — and persisted
firewall state: iptables-save files (`rules.v4`/`rules.v6`,
`sysconfig/iptables`) as chain and rule records, netplan YAML and
`nftables.conf` captured verbatim (64KiB cap) so the evidence surfaces
even where field-level decoding is a later map.

Records carry the pinfo envelope (`Tool`, `ToolVersion`, `RecordType`,
`SourceFilename`, `SourceModified`, `EventTime` — ISO 8601 UTC at fixed
microsecond precision — `TimeKind`, and `Origin`/`Snapshot`/`Residue`
when a stage manifest resolves them). The declared record fields are in
[`contract.yml`](../contract.yml).

As `godaemonhunter gonetwork` with nothing further, the [one binary](../README.md) runs this parser's container-framework batch mode: it
reads the `GONETWORK_*` environment, finds every artefact it handles under the
input tree, writes one output folder per file and prints exactly one JSON
summary line on stdout.

## Input

The evidence tree at `GONETWORK_INPUT_DIR` (default `/input`), mounted
read-only. A `materialise.jsonl` manifest at the input root, when present,
is joined onto every record as `Origin`/`Snapshot`/`Residue`.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `GONETWORK_INPUT_DIR` | `/input` | the evidence tree, recursed |
| `GONETWORK_OUT_DIR` | `/output` | output root, one folder per input file |
| `GONETWORK_KNOWLEDGE_DIR` | `/knowledge` | the Layer-1 knowledge store (optional ro mount); absent = no enrichment |
| `GONETWORK_WORK_DIR` | `/work` | scratch (writable tmpfs); gonetwork needs none but honours it |
| `GONETWORK_FORCE` | `0` | `1/true/yes/on`: rerun items that already have valid output |
| `GONETWORK_LOG_LEVEL` | `info` | `error\|warn\|info\|debug`, stderr only |

## Output

`<OUT_DIR>/<item>/gonetwork.jsonl`; `RecordType` is `hosts_entry`,
`resolv_entry`, `nsswitch_entry`, `tcpwrappers_entry`,
`interfaces_directive`, `interface_profile`, `networkd_profile`,
`nmconnection_profile`, `netplan_config`, `nftables_config`,
`iptables_chain` or `iptables_rule`.

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
  get-sybers/godaemonhunter:latest gonetwork
```

(Build from the **repo root**: the image copies the sibling `pinfo/` module.)

## argv pass-through (debug only, `godaemonhunter gonetwork <args>`)

`-f FILE | -d DIR`, `-q`; records stream to stdout. Exit 0 ok / 1 usage
or fatal / 2 at least one file failed. `--version` prints the version;
`--print-contract` prints `contract.yml`.
