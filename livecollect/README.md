# `livecollect` — the live host as a staged tree

The disk-image path makes an image a host: gomount pulls its `linux-core` /
`macos-core` artefact set into a scratch tree and the layered pipeline runs over
that (see [`../imageitem.go`](../imageitem.go), `gopinfo/diskimage`). **A live
system is a host too.** This package is that same step with the running root
filesystem as the source — no image, no gomount, no decode: it copies the known
artefact surface out of the live root into a scratch tree, and `main` then runs
the unchanged layered pipeline over it.

## Why stage, instead of parsing `/` in place

Every parser discovers its files with one `filepath.WalkDir` of the whole input
root, and that walk **aborts the run as a config error (exit 2) on the first
unreadable directory** (`gopinfo/discover.Files`, `gopinfo/batch`). Pointed at a
live `/` it would descend `/proc`, `/sys`, `/dev` and every mounted filesystem
and die on the first permission denial. Staging:

- visits **only** the known artefact trees — never `/proc`, `/sys`, other mounts;
- is **resilient**: an unreadable or vanished file is logged and skipped, never
  fatal — the opposite of the walk's abort-on-error;
- captures a **point-in-time snapshot** of volatile logs, the forensically
  correct behaviour for a running host.

## The artefact set is data

[`profiles.json`](profiles.json) holds one profile per OS (`linux`, `darwin`),
embedded and validated at load. A profile is:

- **`trees`** — source locations relative to the live root, each copied into the
  stage at the same relative path (a directory recursively, a single file on its
  own). Each `note` says which parsers the tree feeds.
- **`homes`** — `roots` are globs whose every matching directory is a user home,
  and `artefacts` are the paths (files or directories) collected from inside each
  one: shell and session histories, SSH access files, user units, trash.

Adding an OS, or tuning a path, is a data change — not a code change
(docs/standards go §5).

## What staging does to each file

- **Directories** are walked without following symlinked subdirectories, so the
  copy cannot loop or escape the live root.
- **Regular files** are copied, deduped by `(device, inode)` so a file reached by
  two paths (a `/lib → /usr/lib` usrmerge symlink, overlapping trees) is staged
  once, and the original mtime is kept so a record's `SourceModified` is the
  artefact's. An optional `MaxFile` cap skips oversized files.
- **`localtime`** symlinks are staged as their **target string**, because the
  zone name lives in the target, not the TZif content — exactly as an
  image-staged link presents it, so `gohost` reads the zone the same way.
- **Other symlinks** are followed to their target file and its content copied
  (so `/etc/os-release → /usr/lib/os-release` stages the real `os-release`).
- **Sockets, devices and fifos** are skipped.

## Provenance

A [`materialise.jsonl`](../README.md) is written at the stage root — the same
manifest the batch runtime joins onto every record. Each staged file's row
carries its **real on-host absolute path** as `Origin.Path` (independent of
where the collection `Root` pointed — a container may bind-mount the host at
`/host`), its inode, and **no `Snapshot`**: absent means the live volume
(`gopinfo/record`). A metadata row marks the collection's volume as `live`.

## Not an entry point

`livecollect` is a library package; it has no `main`. The live run is driven by
`GODAEMONHUNTER_LIVE` / `GODAEMONHUNTER_LIVE_ROOT` (and a sub-tool's
`<SUBTOOL>_LIVE*`) — see the [top-level README](../README.md).
