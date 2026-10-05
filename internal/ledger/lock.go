package ledger

import (
	"errors"
	"fmt"
	"os"
)

// errLocked is returned by lockFile when another process holds the lock.
var errLocked = errors.New("locked")

// lock takes the exclusive lock that keeps a second gateway from writing the
// same log. Two writers would fork the chain, and the log would then fail
// verification for good. The lock lives in a file next to the log and is
// released when the process exits, however it exits.
func lock(logPath string) (*os.File, error) {
	path := logPath + ".lock"
	f, err := lockFile(path)
	if errors.Is(err, errLocked) {
		return nil, fmt.Errorf("log %s is in use by another process (lock %s)", logPath, path)
	}
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return f, nil
}
