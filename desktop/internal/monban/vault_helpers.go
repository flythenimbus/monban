package monban

import "fmt"

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
