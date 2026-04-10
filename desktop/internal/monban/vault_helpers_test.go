package monban

import "testing"

func TestFindVaultIndex(t *testing.T) {
	vaults := []VaultEntry{
		{Label: "Docs", Path: "/home/user/Documents"},
		{Label: "Keys", Path: "/home/user/.ssh"},
		{Label: "secret.txt", Path: "/home/user/secret.txt", Type: "file"},
	}

	tests := []struct {
		path string
		want int
	}{
		{"/home/user/Documents", 0},
		{"/home/user/.ssh", 1},
		{"/home/user/secret.txt", 2},
		{"/nonexistent", -1},
		{"", -1},
	}

	for _, tt := range tests {
		got := FindVaultIndex(vaults, tt.path)
		if got != tt.want {
			t.Errorf("FindVaultIndex(%q) = %d, want %d", tt.path, got, tt.want)
		}
	}
}

func TestFindVaultIndexEmpty(t *testing.T) {
	got := FindVaultIndex(nil, "/some/path")
	if got != -1 {
		t.Errorf("FindVaultIndex on nil slice = %d, want -1", got)
	}
}

func TestLockVaultEntrySkipsAlreadyLocked(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	// Lock it first
	if err := LockFolder(key, folder); err != nil {
		t.Fatal(err)
	}

	v := VaultEntry{Label: "test", Path: folder}

	// Locking again should be a no-op (not an error)
	if err := LockVaultEntry(key, v); err != nil {
		t.Errorf("locking already-locked vault should not error: %v", err)
	}
}

func TestUnlockVaultEntrySkipsAlreadyUnlocked(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	v := VaultEntry{Label: "test", Path: folder}

	// Folder is already unlocked (never locked)
	if err := UnlockVaultEntry(key, v); err != nil {
		t.Errorf("unlocking already-unlocked vault should not error: %v", err)
	}
}

func TestLockUnlockVaultEntryFile(t *testing.T) {
	path := createTestFile(t)
	key := makeTestKey()

	v := VaultEntry{Label: "secret", Path: path, Type: "file"}

	if err := LockVaultEntry(key, v); err != nil {
		t.Fatalf("lock file vault entry failed: %v", err)
	}

	if !IsFileLocked(path) {
		t.Error("file should be locked")
	}

	if err := UnlockVaultEntry(key, v); err != nil {
		t.Fatalf("unlock file vault entry failed: %v", err)
	}

	if IsFileLocked(path) {
		t.Error("file should be unlocked")
	}
}

func TestLockVaultEntryWithLazyStrictKey(t *testing.T) {
	folder := createTestFolder(t)
	master := makeTestKey() // reuse as master for simplicity
	salt := make([]byte, 32)

	lazyKey, err := DeriveLazyStrictKey(append(master, master...), salt, folder)
	if err != nil {
		t.Fatal(err)
	}

	v := VaultEntry{Label: "test", Path: folder}

	if err := LockVaultEntry(lazyKey, v); err != nil {
		t.Fatalf("lock with lazy key failed: %v", err)
	}

	if !IsLocked(folder) {
		t.Error("folder should be locked")
	}

	if err := UnlockVaultEntry(lazyKey, v); err != nil {
		t.Fatalf("unlock with lazy key failed: %v", err)
	}

	if IsLocked(folder) {
		t.Error("folder should be unlocked")
	}
}
