# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  lists them under `collections` (and, as hosts, under `images`). The
  gomount run gets `TMPDIR` = the work dir, so the spool of a gzip'd
  collection lands on the disk-backed `/work`, never the container's tmpfs.
  An archive is a candidate by name (`.tar.gz`, `.tgz`, `.tar`, `.zip`; the
  acquisition-log sidecar is never one) and an item by content. The
  `live_response/` snapshot of a live-host collection is not read yet (#8).
- **gohost reads `etc/lsb-release`** into the same `os_release` row
  (`DISTRIB_ID` → `Name`/`ID`, `DISTRIB_RELEASE` → `VersionID`,
  `DISTRIB_DESCRIPTION` → `PrettyName`, every key under `Fields`): the
  fallback identity when `etc/os-release` is a symlink into `/usr/lib`
  whose target the evidence lacks — a UAC collection copies `/etc` alone, so
  on Ubuntu/Debian the knowledge store's `OS` was empty where the image
  path had it.
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
