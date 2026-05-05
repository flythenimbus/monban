package monban

import (
	"fmt"
	"os"
)

// --- Types ---

// Vault is the unified handle for a protected entry — folder or file.
// Callers operate through this interface instead of dispatching on
// VaultEntry.Type. Two adapters today (FolderVault, FileVault); add a
// new vault type by implementing this interface and teaching VaultFor.
type Vault interface {
	Label() string
	Path() string
	Type() string

	// IsLocked reports whether the on-disk state is currently encrypted.
	IsLocked() bool

	// Lock encrypts the entry. Idempotent: a no-op when already locked.
	Lock(encKey []byte, p ProgressFunc) error

	// Unlock decrypts the entry. Idempotent: a no-op when already unlocked.
	Unlock(encKey []byte, p ProgressFunc) error

	// PlaintextStats reports filesystem-derived totals (file count + bytes)
	// when the entry is unlocked. Returns (0, 0, nil) when locked or when
	// the path is missing — used for lock-progress pre-walks.
	PlaintextStats() (files, bytes int64, err error)

	// LockedStats reports manifest-derived totals when the entry is
	// locked. Returns (0, 0, nil) when not locked — used for
	// unlock-progress pre-walks.
	LockedStats(encKey []byte) (files, bytes int64, err error)

	// Recover cleans up state left behind by a crashed lock/unlock.
	// Idempotent and no-op when no journal exists; safe to call on every
	// boot. Does not require encKey.
	Recover() error
}

// FolderVault adapts a folder-type VaultEntry to Vault.
type FolderVault struct {
	entry VaultEntry
}

// FileVault adapts a file-type VaultEntry to Vault.
type FileVault struct {
	entry VaultEntry
}

// --- Public functions ---

// VaultFor returns the Vault adapter for a config VaultEntry.
func VaultFor(v VaultEntry) Vault {
	if v.IsFile() {
		return FileVault{entry: v}
	}
	return FolderVault{entry: v}
}

// --- FolderVault methods ---

func (f FolderVault) Label() string  { return f.entry.Label }
func (f FolderVault) Path() string   { return f.entry.Path }
func (f FolderVault) Type() string   { return f.entry.Type }
func (f FolderVault) IsLocked() bool { return IsLocked(f.entry.Path) }

func (f FolderVault) Lock(encKey []byte, p ProgressFunc) error {
	if IsLocked(f.entry.Path) {
		return nil
	}
	if err := LockFolder(encKey, f.entry.Path, p); err != nil {
		return fmt.Errorf("locking vault %s: %w", f.entry.Label, err)
	}
	return nil
}

func (f FolderVault) Unlock(encKey []byte, p ProgressFunc) error {
	if !IsLocked(f.entry.Path) {
		return nil
	}
	if err := UnlockFolder(encKey, f.entry.Path, p); err != nil {
		return fmt.Errorf("unlocking vault %s: %w", f.entry.Label, err)
	}
	return nil
}

func (f FolderVault) PlaintextStats() (files, bytes int64, err error) {
	if IsLocked(f.entry.Path) {
		return 0, 0, nil
	}
	return FolderStats(f.entry.Path)
}

func (f FolderVault) LockedStats(encKey []byte) (files, bytes int64, err error) {
	if !IsLocked(f.entry.Path) {
		return 0, 0, nil
	}
	return ManifestStats(encKey, f.entry.Path)
}

func (f FolderVault) Recover() error {
	return RecoverFromJournal(f.entry.Path)
}

// --- FileVault methods ---

func (f FileVault) Label() string  { return f.entry.Label }
func (f FileVault) Path() string   { return f.entry.Path }
func (f FileVault) Type() string   { return f.entry.Type }
func (f FileVault) IsLocked() bool { return IsFileLocked(f.entry.Path) }

func (f FileVault) Lock(encKey []byte, p ProgressFunc) error {
	if IsFileLocked(f.entry.Path) {
		return nil
	}
	if err := LockFile(encKey, f.entry.Path, p); err != nil {
		return fmt.Errorf("locking file %s: %w", f.entry.Label, err)
	}
	return nil
}

func (f FileVault) Unlock(encKey []byte, p ProgressFunc) error {
	if !IsFileLocked(f.entry.Path) {
		return nil
	}
	if err := UnlockFile(encKey, f.entry.Path, p); err != nil {
		return fmt.Errorf("unlocking file %s: %w", f.entry.Label, err)
	}
	return nil
}

func (f FileVault) PlaintextStats() (files, bytes int64, err error) {
	if IsFileLocked(f.entry.Path) {
		return 0, 0, nil
	}
	info, err := os.Stat(f.entry.Path)
	if err != nil {
		return 0, 0, err
	}
	return 1, info.Size(), nil
}

func (f FileVault) LockedStats(encKey []byte) (files, bytes int64, err error) {
	if !IsFileLocked(f.entry.Path) {
		return 0, 0, nil
	}
	return ManifestStats(encKey, FileVaultDirOf(f.entry.Path))
}

func (f FileVault) Recover() error {
	return RecoverFileFromJournal(f.entry.Path)
}
