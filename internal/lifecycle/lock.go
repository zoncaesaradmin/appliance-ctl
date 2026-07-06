// Package lifecycle implements the CLI skeleton primitives every
// mutating appliance command shares: a host-wide installer lock, an
// atomically-written transaction journal that lets a later invocation
// detect an interrupted prior operation, and dry-run support. See "Fresh
// Install Sequence" step 1 in docs/release-plan.md.
package lifecycle

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// Lock is a host-wide advisory lock backed by flock(2) on a well-known
// file. Only one appliance operation may hold it at a time; a second
// concurrent invocation fails immediately rather than racing.
type Lock struct {
	file *os.File
	path string
}

// AcquireLock takes an exclusive, non-blocking lock on path, creating the
// file if needed. It fails immediately (rather than blocking) when
// another operation already holds the lock, and records this process's
// PID in the file for diagnostics.
func AcquireLock(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: open lock file %s: %w", path, err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder := readHolderPID(f)
		f.Close()
		if holder != "" {
			return nil, fmt.Errorf("lifecycle: another appliance operation is already running (lock held by pid %s)", holder)
		}
		return nil, fmt.Errorf("lifecycle: another appliance operation is already running: %w", err)
	}

	if err := f.Truncate(0); err != nil {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		return nil, fmt.Errorf("lifecycle: truncate lock file %s: %w", path, err)
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		return nil, fmt.Errorf("lifecycle: write pid to lock file %s: %w", path, err)
	}

	return &Lock{file: f, path: path}, nil
}

// Release unlocks and closes the lock file. It does not remove the file,
// so the next AcquireLock reuses it.
func (l *Lock) Release() error {
	if err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN); err != nil {
		l.file.Close()
		return fmt.Errorf("lifecycle: unlock %s: %w", l.path, err)
	}
	return l.file.Close()
}

func readHolderPID(f *os.File) string {
	buf := make([]byte, 32)
	n, err := f.ReadAt(buf, 0)
	if err != nil && n == 0 {
		return ""
	}
	return string(buf[:n])
}
