package lifecycle

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to a temp file in the same directory as
// path, fsyncs it, and renames it into place. Rename is atomic on a
// single POSIX filesystem, so a reader never observes a partially
// written file, and a crash mid-write leaves the original file (or
// nothing, on first write) untouched. Used for the transaction journal
// and, via internal/state, the installed-state record.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // best-effort; no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
