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

func TestCheckVaultOverlap(t *testing.T) {
	vaults := []VaultEntry{
		{Label: "Docs", Path: "/home/user/Documents"},
		{Label: "Keys", Path: "/home/user/.ssh"},
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "no overlap",
			path:    "/home/user/Photos",
			wantErr: false,
		},
		{
			name:    "exact match detected as overlap",
			path:    "/home/user/Documents",
			wantErr: true,
			errMsg:  "inside existing vault",
		},
		{
			name:    "child of existing vault",
			path:    "/home/user/Documents/Work",
			wantErr: true,
			errMsg:  "inside existing vault",
		},
		{
			name:    "deep nested child",
			path:    "/home/user/Documents/Work/Reports/2024",
			wantErr: true,
			errMsg:  "inside existing vault",
		},
		{
			name:    "parent of existing vault",
			path:    "/home/user",
			wantErr: true,
			errMsg:  "ancestor of existing vault",
		},
		{
			name:    "grandparent of existing vault",
			path:    "/home",
			wantErr: true,
			errMsg:  "ancestor of existing vault",
		},
		{
			name:    "sibling with shared prefix",
			path:    "/home/user/DocumentsBackup",
			wantErr: false,
		},
		{
			name:    "sibling with shared prefix and suffix",
			path:    "/home/user/.ssh-old",
			wantErr: false,
		},
		{
			name:    "root as parent",
			path:    "/",
			wantErr: true,
			errMsg:  "ancestor of existing vault",
		},
		{
			name:    "completely unrelated path",
			path:    "/opt/data",
			wantErr: false,
		},
		{
			name:    "empty vaults",
			path:    "/any/path",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := vaults
			if tt.name == "empty vaults" {
				v = nil
			}
			err := CheckVaultOverlap(v, tt.path)
			if tt.wantErr && err == nil {
				t.Errorf("expected error containing %q, got nil", tt.errMsg)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if tt.wantErr && err != nil {
				if got := err.Error(); !contains(got, tt.errMsg) {
					t.Errorf("error %q should contain %q", got, tt.errMsg)
				}
			}
		})
	}
}

func TestCheckVaultOverlapFileVaults(t *testing.T) {
	vaults := []VaultEntry{
		{Label: "secret", Path: "/home/user/Documents/secret.txt", Type: "file"},
	}

	// A folder vault that is parent of the file vault
	err := CheckVaultOverlap(vaults, "/home/user/Documents")
	if err == nil {
		t.Error("expected error: folder is ancestor of file vault path")
	}

	// A folder vault that is child path-wise of the file
	// (file path is not a real directory, but prefix matching still applies)
	err = CheckVaultOverlap(vaults, "/home/user/Documents/secret.txt/nested")
	if err == nil {
		t.Error("expected error: path is inside file vault path")
	}

	// Unrelated path should be fine
	err = CheckVaultOverlap(vaults, "/home/user/Photos")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		findSubstr(s, substr))
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
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
