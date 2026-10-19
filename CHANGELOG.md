# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Flat Layer-2 lane output — one record file per (sub-tool, evidence asset).**
  The hunt sweep (disk images and UAC collections), the single-sub-tool
  image/live runs and the plain batch run now write
  `<OUT_DIR>/<subtool>/<asset-id>.jsonl` instead of the runtime's
  `<subtool>/<image>/<item>/<subtool>.jsonl` tree: no per-artefact directory and
  no duplicated `<subtool>.jsonl` leaf. The asset id is the strongest gomount
  stage-manifest identifier (`disk_serial` → `volume_guid` → `image_sha256`),
  falling back to the item name (loose/live: the host dir name); the per-artefact
  source path is each row's `Origin.Path`, so the collapse loses no provenance.
  Two acquisitions of one disk share an asset id and **merge by appending** within
  a run (byakugan dedupes rows at load); a re-run rebuilds. The **Layer-1
  knowledge store** (`<OUT_DIR>/knowledge/…`) is an internal enrichment tree and
  keeps its per-item layout. A non-JSONL (`<SUBTOOL>_FORMAT=csv`) run is not
  flattened — those per-item/per-table files are preserved verbatim. gopinfo is
  unchanged: it writes its per-item tree into a private temp dir the engine then
  merges (`flatten.go`, `assetid.go`).
- **Evidence-asset identity on every record.** Bumped the shared
  [`gopinfo`](https://github.com/Get-Sybers/gopinfo) runtime to **v0.3.0**,
  which widens the record `Origin` with the frozen gopinfo↔gomount
  asset-identity contract (all `omitempty`): the image-scoped `DiskSerial`
  (drive/container serial — an EWF header `sn`, a VM container id) and
  `DiskID` (GPT disk GUID or MBR signature), and the volume-scoped
  `VolumeGUID`, `PartGUID` and `PartOffset`, joined from the
  `materialise.jsonl` manifest that [gomount](https://github.com/Get-Sybers/gomount)
  **v0.4.0** now writes (image-level keys on the path-less metadata row, the
  volume-scoped keys on every file row). The host's own machine id already
  rode `Host.MachineID`. The join is one shared site in gopinfo's batch
  runtime, so all sixteen daemon parsers inherit the fields with **no
  per-parser change** — a disk image, a UAC collection or a staged tree all
  come out keyed to a resolvable evidence asset, beside the unchanged
  `Image`/`Volume`/`FSUUID`/`Label`/`Path`/`Inode`. Honest nulls stand: a
  field absent for a format or layout is omitted, never synthesised
  (raw/dd/QCOW2 carry no `DiskSerial`; an unpartitioned volume no `PartGUID`;
  a UAC collection's synthetic `[root]` no disk or volume GUID; macOS has no
  machine-id source). `Origin.ImageSHA256` (the acquisition bytes' sha256) is
  part of the same contract and is stamped too: the hunt now pulls the image
  with gomount's `materialise --hash`, so every record carries it. That is one
  extra sequential read of the container per hunt, paid once on the primary
  pull — the Mac System-volume second pass inherits the digest as the
  manifest's metadata default rather than re-hashing the image a second time.

## [0.3.0] - 2026-10-14

### Added
- **UAC collections are hosts.** The archive the Unix-like Artifacts
  Collector ([tclahr/uac](https://github.com/tclahr/uac)) writes —
  `uac-<hostname>-<os>-<timestamp>.tar.gz`, `.tar` or `.zip`, the host's
  files under `[root]/` — is hunted **on** like a disk image: the baked-in
  gomount (≥ the release carrying its `uac` package) reads the archive as an
  image whose root volume is the `[root]/` tree, `materialise --set
  linux-core` stages the daemon parsers' surface out of it, and the layered
  run goes over that stage with the knowledge store at
  `<KNOWLEDGE_DIR>/<archive>/`, the records under
  `<OUT_DIR>/<subtool>/<archive>/`, every record's `Origin` naming the
  archive and `[root]`. `GODAEMONHUNTER_IMAGE` (and a sub-tool's
  `<SUBTOOL>_IMAGE`) may name a collection; without `IMAGE`, every archive
  directly under the input root that `gomount identify` confirms as a
  collection (a volume of fstype `uac`) is hunted beside the disk images,
  a zip or tar of anything else reported and skipped. The summary line
  lists them under `collections` (and, as hosts, under `images`). Every
  gomount run — `identify` as much as `materialise` — gets `TMPDIR` = the
  work dir, so the spool of a gzip'd collection lands on the disk-backed
  `/work`, never the container's tmpfs (nor a `FROM scratch` image's
  missing `/tmp`); a candidate gomount cannot read is skipped with
  gomount's own reason on stderr, and a named collection gets no Mac
  second-pass identify (one host's root tree is never a Data/System pair).
  An archive is a candidate by name (`.tar.gz`, `.tgz`, `.tar`, `.zip`; the
  acquisition-log sidecar is never one) and an item by content. The
  `live_response/` snapshot of a live-host collection is not read yet (#8).
- **gohost reads `etc/lsb-release`** into the `os_release` row shape
  (`DISTRIB_ID` → `Name`/`ID`, `DISTRIB_RELEASE` → `VersionID`,
  `DISTRIB_DESCRIPTION` → `PrettyName`, every key under `Fields`): the
  fallback identity when the staged tree has no os-release identity —
  `etc/os-release` a symlink into `/usr/lib` whose target the evidence
  lacks, staged as its link text (a UAC collection copies `/etc` alone, so
  on Ubuntu/Debian the knowledge store's `OS` was empty where the image
  path had it). Beside a readable os-release the row is recorded as
  `lsb_release` instead: the knowledge store keeps the first `os_release`
  row in path order, and `etc_lsb-release` sorts before `etc_os-release`,
  so the LSB description would otherwise outrank `PRETTY_NAME` on every
  Ubuntu host.
- The conformance gate of the get-sybers standard (DX_DFIR
  `docs/reference/build-and-test.md`): `make conform` (gofmt, vet, build,
  shuffled tests with coverage, `go mod tidy -diff`, a macOS cross-compile, a
  `go:generate` drift check and `scripts/structlint.sh`), `make lint`
  (golangci-lint v2, `.golangci.yml`) and `make vuln` (govulncheck), run by the
  `CI` workflow on pull requests and `main` with `all_green` as the one
  required status check.
- Repository hygiene: `.editorconfig`, `.gitattributes`, `.shellcheckrc`,
  Dependabot (actions and Go modules, weekly, grouped), `CODEOWNERS`, a
  security policy and a pull-request template.

### Fixed
- The findings the new lint gate surfaced: gofmt and import grouping on five
  files, unchecked best-effort writes made explicit, and two local names that
  shadowed the `real` and `max` builtins renamed.

## [0.2.1] - 2026-10-03

The last release before this changelog was started; see the git history for
this and the earlier tags.

## [0.2.0] - 2026-10-03

## [0.1.0] - 2026-09-28

[Unreleased]: https://github.com/Get-Sybers/godaemonhunter/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Get-Sybers/godaemonhunter/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/Get-Sybers/godaemonhunter/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Get-Sybers/godaemonhunter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Get-Sybers/godaemonhunter/releases/tag/v0.1.0
