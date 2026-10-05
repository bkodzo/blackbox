package ledger

import (
	"errors"
	"os"
	"syscall"
)

// errorSharingViolation is returned when another handle has the file open.
const errorSharingViolation syscall.Errno = 32

func lockFile(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// A share mode of 0 denies every other open until this handle is closed.
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, errorSharingViolation) {
			return nil, errLocked
		}
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}
