//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly || windows)

package ledger

import "os"

// lockFile does nothing on platforms without a supported file lock; run only
// one gateway per log there.
func lockFile(string) (*os.File, error) { return nil, nil }
