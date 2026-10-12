//go:build !unix

package livecollect

import "io/fs"

// statKey has no file identity to report off a non-unix host; live mode is
// unix-only, so this only keeps the package building on other platforms.
func statKey(fs.FileInfo) (dev, ino uint64, ok bool) { return 0, 0, false }
