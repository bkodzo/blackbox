package ledger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// errLocked is returned by lockFile when another process holds the lock.
var errLocked = errors.New("locked")

// lock takes the exclusive lock that keeps a second gateway from writing the
// same file, what being "log" or "checkpoint file" for messages. Two writers
// would fork the log's chain, or mix two logs' checkpoints in one file, and
// either would then fail verification for good. The lock lives in a file
// next to the target, after following symlinks, so every path to the same
// file shares one lock. It is released when the process exits, however it
// exits.
func lock(target, what string) (*os.File, error) {
	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		target = resolved
	}
	path := target + ".lock"
	f, err := lockFile(path)
	if errors.Is(err, errLocked) {
		return nil, fmt.Errorf("%s %s is in use by another process (lock %s)", what, target, path)
	}
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return f, nil
}
