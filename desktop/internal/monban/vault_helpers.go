package monban

import (
	"fmt"
	"path/filepath"
	"strings"
)

// LockVaultEntry locks a single vault entry (file or folder), skipping if already locked.
func LockVaultEntry(encKey []byte, v VaultEntry) error {
	if v.IsFile() {
		if IsFileLocked(v.Path) {
			return nil
		}
		if err := LockFile(encKey, v.Path); err != nil {
			return fmt.Errorf("locking file %s: %w", v.Label, err)
		}
	} else {
		if IsLocked(v.Path) {
			return nil
		}
		if err := LockFolder(encKey, v.Path); err != nil {
			return fmt.Errorf("locking vault %s: %w", v.Label, err)
		}
	}
	return nil
}

// UnlockVaultEntry unlocks a single vault entry (file or folder), skipping if already unlocked.
func UnlockVaultEntry(encKey []byte, v VaultEntry) error {
	if v.IsFile() {
		if !IsFileLocked(v.Path) {
			return nil
		}
		if err := UnlockFile(encKey, v.Path); err != nil {
			return fmt.Errorf("unlocking file %s: %w", v.Label, err)
		}
	} else {
		if !IsLocked(v.Path) {
			return nil
		}
		if err := UnlockFolder(encKey, v.Path); err != nil {
			return fmt.Errorf("unlocking vault %s: %w", v.Label, err)
		}
	}
	return nil
}

// FindVaultIndex returns the index of a vault entry matching the given path, or -1 if not found.
func FindVaultIndex(vaults []VaultEntry, path string) int {
	for i, v := range vaults {
		if v.Path == path {
			return i
		}
	}
	return -1
}

// CheckVaultOverlap checks whether the given path is nested inside or is an
// ancestor of any existing vault. Returns a non-nil error describing the
// conflict if an overlap is detected.
func CheckVaultOverlap(vaults []VaultEntry, path string) error {
	normNew := withTrailingSep(filepath.Clean(path))

	for _, v := range vaults {
		normExisting := withTrailingSep(filepath.Clean(v.Path))

		if strings.HasPrefix(normNew, normExisting) {
			return fmt.Errorf("path is inside existing vault %q", v.Path)
		}
		if strings.HasPrefix(normExisting, normNew) {
			return fmt.Errorf("path is an ancestor of existing vault %q", v.Path)
		}
	}
	return nil
}

// withTrailingSep ensures the path ends with a separator. For the root path
// "/" this returns "/" (already ends with separator).
func withTrailingSep(p string) string {
	if strings.HasSuffix(p, string(filepath.Separator)) {
		return p
	}
	return p + string(filepath.Separator)
}
