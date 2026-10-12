//go:build unix

package livecollect

import (
	"io/fs"
	"syscall"
)

// statKey returns the (device, inode) identity of a staged file, used to copy a
// file reached by more than one path (a usrmerge /lib -> /usr/lib symlink,
// overlapping trees) exactly once, and to stamp the inode into the manifest.
// Both of the operating systems live mode supports — linux and darwin — carry
// these in syscall.Stat_t.
func statKey(fi fs.FileInfo) (dev, ino uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true
}
