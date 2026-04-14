package monban

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeTestKey() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func createTestFolder(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	folder := filepath.Join(dir, "testfolder")
	_ = os.MkdirAll(folder, 0700)
	_ = os.MkdirAll(filepath.Join(folder, "sub"), 0700)
	_ = os.WriteFile(filepath.Join(folder, "file1.txt"), []byte("hello"), 0600)
	_ = os.WriteFile(filepath.Join(folder, "file2.txt"), []byte("world"), 0600)
	_ = os.WriteFile(filepath.Join(folder, "sub", "nested.txt"), []byte("nested content"), 0600)
	return folder
}

func TestLockUnlockRoundTrip(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	// Lock
	if err := LockFolder(key, folder); err != nil {
		t.Fatalf("lock failed: %v", err)
	}

	// Verify: originals gone
	if _, err := os.Stat(filepath.Join(folder, "file1.txt")); !os.IsNotExist(err) {
		t.Error("file1.txt should be removed after lock")
	}

	// Verify: .monban-data exists with .enc files
	dataPath := filepath.Join(folder, ".monban-data")
	if _, err := os.Stat(dataPath); err != nil {
		t.Fatal(".monban-data directory should exist")
	}

	// Verify: encrypted manifest exists
	if _, err := os.Stat(filepath.Join(folder, ".monban-manifest.enc")); err != nil {
		t.Fatal(".monban-manifest.enc should exist")
	}

	// Verify: IsLocked returns true
	if !IsLocked(folder) {
		t.Error("IsLocked should return true after lock")
	}

	// Unlock
	if err := UnlockFolder(key, folder); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}

	// Verify: files restored
	data1, err := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if err != nil {
		t.Fatal("file1.txt should be restored")
	}
	if string(data1) != "hello" {
		t.Errorf("file1.txt content: got %q, want %q", data1, "hello")
	}

	data2, _ := os.ReadFile(filepath.Join(folder, "file2.txt"))
	if string(data2) != "world" {
		t.Errorf("file2.txt content: got %q, want %q", data2, "world")
	}

	nested, _ := os.ReadFile(filepath.Join(folder, "sub", "nested.txt"))
	if string(nested) != "nested content" {
		t.Errorf("nested.txt content: got %q, want %q", nested, "nested content")
	}

	// Verify: .monban-data cleaned up
	if _, err := os.Stat(dataPath); !os.IsNotExist(err) {
		t.Error(".monban-data should be removed after unlock")
	}

	// Verify: IsLocked returns false
	if IsLocked(folder) {
		t.Error("IsLocked should return false after unlock")
	}
}

func TestLockIncrementalUnchanged(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	// First lock
	_ = LockFolder(key, folder)
	_ = UnlockFolder(key, folder)

	// Add a new file
	_ = os.WriteFile(filepath.Join(folder, "new.txt"), []byte("new file"), 0600)

	// Second lock — should encrypt new file, reuse existing .enc for unchanged
	if err := LockFolder(key, folder); err != nil {
		t.Fatalf("incremental lock failed: %v", err)
	}

	// Unlock and verify all files present
	_ = UnlockFolder(key, folder)

	newContent, err := os.ReadFile(filepath.Join(folder, "new.txt"))
	if err != nil {
		t.Fatal("new.txt should exist after unlock")
	}
	if string(newContent) != "new file" {
		t.Errorf("new.txt: got %q, want %q", newContent, "new file")
	}

	// Original files should still be there
	data1, _ := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if string(data1) != "hello" {
		t.Error("file1.txt should be preserved")
	}
}

func TestLockIncrementalModified(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	// First lock
	_ = LockFolder(key, folder)
	_ = UnlockFolder(key, folder)

	// Modify a file (change content and ensure mod time differs)
	time.Sleep(10 * time.Millisecond)
	_ = os.WriteFile(filepath.Join(folder, "file1.txt"), []byte("modified!"), 0600)

	// Re-lock
	if err := LockFolder(key, folder); err != nil {
		t.Fatalf("lock after modify failed: %v", err)
	}

	// Unlock and verify modification persisted
	_ = UnlockFolder(key, folder)

	data, _ := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if string(data) != "modified!" {
		t.Errorf("file1.txt: got %q, want %q", data, "modified!")
	}
}

func TestLockDeletedFile(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	// First lock
	_ = LockFolder(key, folder)
	_ = UnlockFolder(key, folder)

	// Delete a file
	_ = os.Remove(filepath.Join(folder, "file2.txt"))

	// Re-lock — stale .enc should be cleaned up
	if err := LockFolder(key, folder); err != nil {
		t.Fatalf("lock after delete failed: %v", err)
	}

	// Unlock — file2.txt should not exist
	_ = UnlockFolder(key, folder)

	if _, err := os.Stat(filepath.Join(folder, "file2.txt")); !os.IsNotExist(err) {
		t.Error("deleted file should not reappear after unlock")
	}

	// Other files should still be there
	data1, _ := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if string(data1) != "hello" {
		t.Error("file1.txt should still exist")
	}
}

func TestRecoverFromJournalEncrypting(t *testing.T) {
	folder := createTestFolder(t)

	// Simulate crash during encrypting phase: journal exists, partial .monban-data
	_ = os.MkdirAll(filepath.Join(folder, ".monban-data"), 0700)
	_ = os.WriteFile(filepath.Join(folder, ".monban-data", "partial.enc"), []byte("junk"), 0600)

	journal := &JournalState{
		Operation: "lock",
		Folder:    folder,
		State:     "encrypting",
		Timestamp: time.Now(),
	}
	_ = writeJournal(folder, journal)

	// Recovery should clean up .monban-data and journal
	err := RecoverFromJournal(folder)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(folder, ".monban-data")); !os.IsNotExist(err) {
		t.Error(".monban-data should be removed during recovery")
	}
	if _, err := os.Stat(journalPath(folder)); !os.IsNotExist(err) {
		t.Error("journal should be removed during recovery")
	}

	// Original files should still be intact
	data, _ := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if string(data) != "hello" {
		t.Error("originals should be intact after recovery from encrypting phase")
	}
}

func TestIsLockedFalseWithoutManifest(t *testing.T) {
	dir := t.TempDir()
	if IsLocked(dir) {
		t.Error("should not be locked without manifest")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1 KB"},
		{1536, "1.5 KB"},
		{1048576, "1 MB"},
		{1073741824, "1 GB"},
	}

	for _, tt := range tests {
		got := FormatBytes(tt.input)
		if got != tt.expected {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestRecoverFromJournalRemovingOriginals(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	// Do a real lock first so .monban-data and manifest exist
	_ = LockFolder(key, folder)

	// Now simulate crash during "removing-originals" — journal says removing but
	// some originals might still be around (shouldn't matter, they're already encrypted)
	journal := &JournalState{
		Operation: "lock",
		Folder:    folder,
		State:     "removing-originals",
		Timestamp: time.Now(),
	}
	_ = writeJournal(folder, journal)

	err := RecoverFromJournal(folder)
	if err != nil {
		t.Fatal(err)
	}

	// Journal should be cleaned up
	if _, err := os.Stat(journalPath(folder)); !os.IsNotExist(err) {
		t.Error("journal should be removed")
	}

	// Encrypted data should still be intact — can still unlock
	if err := UnlockFolder(key, folder); err != nil {
		t.Fatalf("should still unlock after recovery: %v", err)
	}
}

func TestRecoverFromJournalRemovingEncrypted(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	// Lock then start unlocking
	_ = LockFolder(key, folder)
	// Decrypt files manually so they exist
	manifest, _ := loadEncryptedManifest(key, folder)
	_ = decryptFilesInPlace(key, manifest, folder)

	// Simulate crash during "removing-encrypted"
	journal := &JournalState{
		Operation: "unlock",
		Folder:    folder,
		State:     "removing-encrypted",
		Timestamp: time.Now(),
	}
	_ = writeJournal(folder, journal)

	err := RecoverFromJournal(folder)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(journalPath(folder)); !os.IsNotExist(err) {
		t.Error("journal should be removed")
	}

	// Decrypted files should be present
	data, _ := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if string(data) != "hello" {
		t.Error("decrypted files should be intact")
	}
}

func TestUnlockWithWrongKey(t *testing.T) {
	folder := createTestFolder(t)
	rightKey := makeTestKey()
	wrongKey := bytes.Repeat([]byte{0x99}, 32)

	_ = LockFolder(rightKey, folder)

	err := UnlockFolder(wrongKey, folder)
	if err == nil {
		t.Error("unlock with wrong key should fail")
	}
}

func TestLockEmptyFolder(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "empty")
	_ = os.MkdirAll(folder, 0700)
	key := makeTestKey()

	if err := LockFolder(key, folder); err != nil {
		t.Fatalf("locking empty folder should succeed: %v", err)
	}

	if err := UnlockFolder(key, folder); err != nil {
		t.Fatalf("unlocking empty folder should succeed: %v", err)
	}
}

func TestLockPreservesFilePermissions(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "perms")
	_ = os.MkdirAll(folder, 0700)
	_ = os.WriteFile(filepath.Join(folder, "exec.sh"), []byte("#!/bin/sh"), 0755)
	_ = os.WriteFile(filepath.Join(folder, "readonly.txt"), []byte("ro"), 0444)

	key := makeTestKey()
	_ = LockFolder(key, folder)
	_ = UnlockFolder(key, folder)

	info1, _ := os.Stat(filepath.Join(folder, "exec.sh"))
	if info1.Mode().Perm() != 0755 {
		t.Errorf("exec.sh permissions: got %o, want 0755", info1.Mode().Perm())
	}

	info2, _ := os.Stat(filepath.Join(folder, "readonly.txt"))
	if info2.Mode().Perm() != 0444 {
		t.Errorf("readonly.txt permissions: got %o, want 0444", info2.Mode().Perm())
	}
}

func TestFolderSize(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), bytes.Repeat([]byte("x"), 1000), 0600)
	_ = os.WriteFile(filepath.Join(dir, "b.txt"), bytes.Repeat([]byte("y"), 500), 0600)

	size, err := FolderSize(dir)
	if err != nil {
		t.Fatal(err)
	}
	if size != 1500 {
		t.Errorf("FolderSize: got %d, want 1500", size)
	}
}

func TestFolderSizeEmpty(t *testing.T) {
	dir := t.TempDir()
	size, err := FolderSize(dir)
	if err != nil {
		t.Fatal(err)
	}
	if size != 0 {
		t.Errorf("empty folder size: got %d, want 0", size)
	}
}

func TestCountFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0600)
	_ = os.MkdirAll(filepath.Join(dir, "sub"), 0700)
	_ = os.WriteFile(filepath.Join(dir, "sub", "c.txt"), []byte("c"), 0600)

	count, err := CountFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("CountFiles: got %d, want 3", count)
	}
}

func TestCountFilesEmpty(t *testing.T) {
	dir := t.TempDir()
	count, err := CountFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("empty dir count: got %d, want 0", count)
	}
}

func TestFreeSpace(t *testing.T) {
	dir := t.TempDir()
	free, err := FreeSpace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if free <= 0 {
		t.Errorf("FreeSpace should be positive, got %d", free)
	}
}

func TestHashedEncName(t *testing.T) {
	name1 := hashedEncName("file.txt")
	name2 := hashedEncName("other.txt")
	name3 := hashedEncName("file.txt")

	if name1 == name2 {
		t.Error("different paths should produce different hashed names")
	}
	if name1 != name3 {
		t.Error("same path should produce same hashed name")
	}
	if filepath.Ext(name1) != ".enc" {
		t.Errorf("hashed name should end with .enc, got %s", name1)
	}
}

func TestFileUnchanged(t *testing.T) {
	now := time.Now()
	fi := fileInfo{size: 100, modTime: now}
	entry := ManifestEntry{Size: 100, ModTime: now}

	if !fileUnchanged(fi, entry) {
		t.Error("identical size and modTime should be unchanged")
	}

	fi2 := fileInfo{size: 200, modTime: now}
	if fileUnchanged(fi2, entry) {
		t.Error("different size should be changed")
	}

	fi3 := fileInfo{size: 100, modTime: now.Add(time.Second)}
	if fileUnchanged(fi3, entry) {
		t.Error("different modTime should be changed")
	}
}

func TestLockMultipleCycles(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	for i := 0; i < 5; i++ {
		if err := LockFolder(key, folder); err != nil {
			t.Fatalf("lock cycle %d failed: %v", i, err)
		}
		if err := UnlockFolder(key, folder); err != nil {
			t.Fatalf("unlock cycle %d failed: %v", i, err)
		}
	}

	// Verify files still intact after 5 cycles
	data, _ := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if string(data) != "hello" {
		t.Error("file content should survive multiple lock/unlock cycles")
	}
}

// --- Single file vault tests ---

func createTestFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	_ = os.WriteFile(path, []byte("secret content"), 0644)
	return path
}

func TestLockUnlockFileRoundTrip(t *testing.T) {
	path := createTestFile(t)
	key := makeTestKey()

	// Lock
	if err := LockFile(key, path); err != nil {
		t.Fatalf("lock file failed: %v", err)
	}

	// Original should be gone
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("original file should be removed after lock")
	}

	// Vault directory should exist with encrypted data and manifest
	vaultDir := fileVaultDir(path)
	if _, err := os.Stat(filepath.Join(vaultDir, "data.enc")); err != nil {
		t.Error("data.enc should exist in vault dir after lock")
	}
	if _, err := os.Stat(filepath.Join(vaultDir, ".monban-manifest.enc")); err != nil {
		t.Error(".monban-manifest.enc should exist in vault dir after lock")
	}

	// Original filename should not appear in vault dir
	entries, _ := os.ReadDir(vaultDir)
	for _, e := range entries {
		if e.Name() == "secret.txt" {
			t.Error("original filename should not appear in vault directory")
		}
	}

	// IsFileLocked should return true
	if !IsFileLocked(path) {
		t.Error("IsFileLocked should return true after lock")
	}

	// Unlock
	if err := UnlockFile(key, path); err != nil {
		t.Fatalf("unlock file failed: %v", err)
	}

	// Content restored
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("file should be restored after unlock")
	}
	if string(data) != "secret content" {
		t.Errorf("content: got %q, want %q", data, "secret content")
	}

	// Vault directory cleaned up
	if _, err := os.Stat(vaultDir); !os.IsNotExist(err) {
		t.Error("vault directory should be removed after unlock")
	}

	// IsFileLocked should return false
	if IsFileLocked(path) {
		t.Error("IsFileLocked should return false after unlock")
	}
}

func TestLockFilePreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exec.sh")
	_ = os.WriteFile(path, []byte("#!/bin/sh\necho hi"), 0755)

	key := makeTestKey()
	_ = LockFile(key, path)
	_ = UnlockFile(key, path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("permissions: got %o, want 0755", info.Mode().Perm())
	}
}

func TestLockFilePreservesModTime(t *testing.T) {
	path := createTestFile(t)
	fixedTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	_ = os.Chtimes(path, fixedTime, fixedTime)

	key := makeTestKey()
	_ = LockFile(key, path)
	_ = UnlockFile(key, path)

	info, _ := os.Stat(path)
	if !info.ModTime().Equal(fixedTime) {
		t.Errorf("modTime: got %v, want %v", info.ModTime(), fixedTime)
	}
}

func TestLockFileWrongKey(t *testing.T) {
	path := createTestFile(t)
	rightKey := makeTestKey()
	wrongKey := bytes.Repeat([]byte{0x99}, 32)

	_ = LockFile(rightKey, path)

	err := UnlockFile(wrongKey, path)
	if err == nil {
		t.Error("unlock with wrong key should fail")
	}
}

func TestLockFileMultipleCycles(t *testing.T) {
	path := createTestFile(t)
	key := makeTestKey()

	for i := 0; i < 5; i++ {
		if err := LockFile(key, path); err != nil {
			t.Fatalf("lock cycle %d failed: %v", i, err)
		}
		if err := UnlockFile(key, path); err != nil {
			t.Fatalf("unlock cycle %d failed: %v", i, err)
		}
	}

	data, _ := os.ReadFile(path)
	if string(data) != "secret content" {
		t.Error("content should survive multiple lock/unlock cycles")
	}
}

func TestIsFileLockedFalseWithoutVaultDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.txt")
	if IsFileLocked(path) {
		t.Error("should not be locked without vault directory")
	}
}

func TestRecoverFileFromJournalEncrypting(t *testing.T) {
	path := createTestFile(t)

	// Simulate crash during encrypting: vault dir with partial data + journal
	vaultDir := fileVaultDir(path)
	_ = os.MkdirAll(vaultDir, 0700)
	_ = os.WriteFile(filepath.Join(vaultDir, "data.enc"), []byte("partial"), 0600)

	journal := &JournalState{
		Operation: "lock",
		Folder:    path,
		State:     "encrypting",
		Timestamp: time.Now(),
	}
	_ = writeJournal(vaultDir, journal)

	if err := RecoverFileFromJournal(path); err != nil {
		t.Fatal(err)
	}

	// Vault dir should be removed entirely
	if _, err := os.Stat(vaultDir); !os.IsNotExist(err) {
		t.Error("vault dir should be removed during recovery")
	}

	// Original should still be intact
	data, _ := os.ReadFile(path)
	if string(data) != "secret content" {
		t.Error("original should be intact after recovery")
	}
}

func TestRecoverFileFromJournalRemovingEncrypted(t *testing.T) {
	path := createTestFile(t)
	key := makeTestKey()

	// Lock, then decrypt manually, then simulate crash during "removing-encrypted"
	_ = LockFile(key, path)
	vaultDir := fileVaultDir(path)
	_ = DecryptFile(key, filepath.Join(vaultDir, "data.enc"), path)

	journal := &JournalState{
		Operation: "unlock",
		Folder:    path,
		State:     "removing-encrypted",
		Timestamp: time.Now(),
	}
	_ = writeJournal(vaultDir, journal)

	if err := RecoverFileFromJournal(path); err != nil {
		t.Fatal(err)
	}

	// Vault dir should be cleaned up
	if _, err := os.Stat(vaultDir); !os.IsNotExist(err) {
		t.Error("vault dir should be removed during recovery")
	}

	// Decrypted file should be intact
	data, _ := os.ReadFile(path)
	if string(data) != "secret content" {
		t.Error("decrypted file should be intact")
	}
}

func TestRecoverFileFromJournalNoJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nojournal.txt")
	// Should be a no-op, no error
	if err := RecoverFileFromJournal(path); err != nil {
		t.Errorf("should not error without journal: %v", err)
	}
}

func TestLockFileLargeContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.bin")
	// 256KB to exercise multiple encryption chunks (64KB each)
	content := bytes.Repeat([]byte{0xAB}, 256*1024)
	_ = os.WriteFile(path, content, 0600)

	key := makeTestKey()
	_ = LockFile(key, path)
	_ = UnlockFile(key, path)

	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, content) {
		t.Error("large file content should survive lock/unlock")
	}
}

func TestFileVaultDirIsOpaque(t *testing.T) {
	dir1 := fileVaultDir("/path/to/secret.txt")
	dir2 := fileVaultDir("/path/to/other.txt")
	dir3 := fileVaultDir("/path/to/secret.txt")

	if dir1 == dir2 {
		t.Error("different files should produce different vault dirs")
	}
	if dir1 != dir3 {
		t.Error("same file should produce same vault dir")
	}
	// Directory name should not contain the original filename
	if filepath.Base(dir1) == "secret.txt" {
		t.Error("vault dir name should not be the original filename")
	}
}

func TestLockWithOneKeyUnlockWithAnother(t *testing.T) {
	// Simulates the lazy_strict scenario: lock with lazyStrictKey, unlock with same key
	folder := createTestFolder(t)
	master := bytes.Repeat([]byte{0x11}, 64)
	salt := bytes.Repeat([]byte{0x22}, 32)

	encKey, _ := DeriveEncryptionKey(master, salt)
	lazyKey, _ := DeriveLazyStrictKey(master, salt, folder)

	// Lock with lazyStrictKey
	if err := LockFolder(lazyKey, folder); err != nil {
		t.Fatalf("lock with lazy key failed: %v", err)
	}

	// Unlock with encKey should fail (wrong key)
	if err := UnlockFolder(encKey, folder); err == nil {
		t.Error("unlock with encKey should fail for lazy-strict-encrypted vault")
	}

	// Unlock with correct lazyStrictKey should succeed
	if err := UnlockFolder(lazyKey, folder); err != nil {
		t.Fatalf("unlock with lazy key failed: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if string(data) != "hello" {
		t.Error("file content should be preserved")
	}
}

func TestLockFileWithLazyStrictKey(t *testing.T) {
	path := createTestFile(t)
	master := bytes.Repeat([]byte{0x11}, 64)
	salt := bytes.Repeat([]byte{0x22}, 32)

	lazyKey, _ := DeriveLazyStrictKey(master, salt, path)

	if err := LockFile(lazyKey, path); err != nil {
		t.Fatalf("lock file with lazy key failed: %v", err)
	}

	if !IsFileLocked(path) {
		t.Error("file should be locked")
	}

	if err := UnlockFile(lazyKey, path); err != nil {
		t.Fatalf("unlock file with lazy key failed: %v", err)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "secret content" {
		t.Error("file content should be preserved")
	}
}

func TestReencryptFolderWithDifferentKey(t *testing.T) {
	// Simulates mode switch: decrypt with key A, re-encrypt with key B
	folder := createTestFolder(t)
	master := bytes.Repeat([]byte{0x11}, 64)
	salt := bytes.Repeat([]byte{0x22}, 32)

	encKey, _ := DeriveEncryptionKey(master, salt)
	lazyKey, _ := DeriveLazyStrictKey(master, salt, folder)

	// Start encrypted with encKey
	if err := LockFolder(encKey, folder); err != nil {
		t.Fatal(err)
	}

	// Decrypt with encKey
	if err := UnlockFolder(encKey, folder); err != nil {
		t.Fatal(err)
	}

	// Re-encrypt with lazyStrictKey
	if err := LockFolder(lazyKey, folder); err != nil {
		t.Fatal(err)
	}

	// encKey should not work anymore
	if err := UnlockFolder(encKey, folder); err == nil {
		t.Error("old encKey should not decrypt after re-encryption with lazy key")
	}

	// lazyStrictKey should work
	if err := UnlockFolder(lazyKey, folder); err != nil {
		t.Fatalf("lazy key should decrypt after re-encryption: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if string(data) != "hello" {
		t.Error("content should survive re-encryption")
	}
}

func TestReencryptFileWithDifferentKey(t *testing.T) {
	path := createTestFile(t)
	master := bytes.Repeat([]byte{0x11}, 64)
	salt := bytes.Repeat([]byte{0x22}, 32)

	encKey, _ := DeriveEncryptionKey(master, salt)
	lazyKey, _ := DeriveLazyStrictKey(master, salt, path)

	// Encrypt with encKey
	if err := LockFile(encKey, path); err != nil {
		t.Fatal(err)
	}

	// Decrypt with encKey
	if err := UnlockFile(encKey, path); err != nil {
		t.Fatal(err)
	}

	// Re-encrypt with lazyStrictKey
	if err := LockFile(lazyKey, path); err != nil {
		t.Fatal(err)
	}

	// lazyStrictKey should work
	if err := UnlockFile(lazyKey, path); err != nil {
		t.Fatalf("lazy key should work: %v", err)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "secret content" {
		t.Error("content should survive re-encryption")
	}
}

func TestCollectFilesSkipsMonbanFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "real.txt"), []byte("keep"), 0600)
	_ = os.WriteFile(filepath.Join(dir, ".monban-journal.json"), []byte("{}"), 0600)
	_ = os.WriteFile(filepath.Join(dir, ".monban-manifest.enc"), []byte("enc"), 0600)
	_ = os.MkdirAll(filepath.Join(dir, ".monban-data"), 0700)
	_ = os.WriteFile(filepath.Join(dir, ".monban-data", "a.enc"), []byte("enc"), 0600)

	files, err := collectFiles(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].relPath != "real.txt" {
		t.Errorf("expected real.txt, got %s", files[0].relPath)
	}
}

// --- Security tests ---

func TestCollectFilesSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "real.txt"), []byte("real"), 0600)

	// Create a symlink to a file outside the vault
	outside := filepath.Join(t.TempDir(), "secret.txt")
	_ = os.WriteFile(outside, []byte("secret"), 0600)
	_ = os.Symlink(outside, filepath.Join(dir, "link.txt"))

	files, err := collectFiles(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file (symlink skipped), got %d", len(files))
	}
	if files[0].relPath != "real.txt" {
		t.Errorf("expected real.txt, got %s", files[0].relPath)
	}
}

func TestCollectFilesSkipsSymlinkDirs(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "real.txt"), []byte("real"), 0600)

	// Create a symlink to an outside directory
	outsideDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(outsideDir, "exfil.txt"), []byte("sensitive"), 0600)
	_ = os.Symlink(outsideDir, filepath.Join(dir, "linked_dir"))

	files, err := collectFiles(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Only real.txt should be collected, not files from the symlinked dir
	for _, f := range files {
		if f.relPath == filepath.Join("linked_dir", "exfil.txt") {
			t.Error("symlinked directory contents should not be collected")
		}
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
}

func TestLockFolderIgnoresSymlinks(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "vault")
	_ = os.MkdirAll(folder, 0700)
	_ = os.WriteFile(filepath.Join(folder, "real.txt"), []byte("keep"), 0600)

	// Symlink pointing outside the vault
	outside := filepath.Join(dir, "outside.txt")
	_ = os.WriteFile(outside, []byte("do not encrypt"), 0600)
	_ = os.Symlink(outside, filepath.Join(folder, "escape.txt"))

	key := makeTestKey()
	if err := LockFolder(key, folder); err != nil {
		t.Fatalf("lock failed: %v", err)
	}
	if err := UnlockFolder(key, folder); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}

	// The outside file should be untouched
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal("outside file should still exist")
	}
	if string(data) != "do not encrypt" {
		t.Error("outside file should not be modified")
	}

	// Only real.txt should be restored (symlink was skipped)
	data, err = os.ReadFile(filepath.Join(folder, "real.txt"))
	if err != nil {
		t.Fatal("real.txt should be restored")
	}
	if string(data) != "keep" {
		t.Errorf("real.txt: got %q, want %q", data, "keep")
	}
}

func TestValidateManifestPathRejectsTraversal(t *testing.T) {
	root := "/home/user/vault"

	tests := []struct {
		path    string
		wantErr bool
	}{
		{"file.txt", false},
		{"sub/file.txt", false},
		{"../../../etc/passwd", true},
		{"sub/../../../etc/passwd", true},
		{"/etc/passwd", true},
		{"..", true},
		{"sub/../../outside", true},
	}

	for _, tt := range tests {
		err := validateManifestPath(tt.path, root)
		if tt.wantErr && err == nil {
			t.Errorf("validateManifestPath(%q) should fail", tt.path)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("validateManifestPath(%q) should pass: %v", tt.path, err)
		}
	}
}

func TestDecryptRejectsTraversalInManifest(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "vault")
	_ = os.MkdirAll(filepath.Join(folder, ".monban-data"), 0700)

	key := makeTestKey()

	// Create a malicious manifest with path traversal
	manifest := &Manifest{
		Version: 1,
		Files: []ManifestEntry{
			{
				Path:    "../../../tmp/pwned",
				EncName: "abc123.enc",
				Size:    5,
				Mode:    0600,
			},
		},
	}

	err := decryptFilesInPlace(key, manifest, folder)
	if err == nil {
		t.Error("decryption should fail with path traversal in manifest")
	}
}

func TestEncryptBytesDecryptBytesRoundTrip(t *testing.T) {
	key := makeTestKey()
	plaintext := []byte("secret manifest data")

	encrypted, err := EncryptBytes(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := DecryptBytes(key, encrypted)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptBytesWrongKey(t *testing.T) {
	key := makeTestKey()
	wrongKey := bytes.Repeat([]byte{0x99}, 32)

	encrypted, err := EncryptBytes(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptBytes(wrongKey, encrypted)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestEncryptBytesEmptyPlaintext(t *testing.T) {
	key := makeTestKey()

	encrypted, err := EncryptBytes(key, []byte{})
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptBytes(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty, got %d bytes", len(decrypted))
	}
}

func TestManifestNoPlaintextTempFile(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "vault")
	_ = os.MkdirAll(folder, 0700)

	key := makeTestKey()
	manifest := &Manifest{
		Version: 1,
		Files: []ManifestEntry{
			{Path: "test.txt", EncName: "abc.enc", Size: 5, Mode: 0600},
		},
	}

	if err := writeEncryptedManifest(key, folder, manifest); err != nil {
		t.Fatal(err)
	}

	// Verify no .tmp file exists
	tmpPath := filepath.Join(folder, ".monban-manifest.enc.tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("plaintext temp file should not exist after write")
	}

	// Verify the encrypted manifest can be loaded back
	loaded, err := loadEncryptedManifest(key, folder)
	if err != nil {
		t.Fatalf("loading manifest failed: %v", err)
	}
	if len(loaded.Files) != 1 || loaded.Files[0].Path != "test.txt" {
		t.Error("manifest content mismatch after round trip")
	}
}

func TestRecoverFromJournalDecryptingCleansPartialFiles(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	// Lock the folder so encrypted data exists
	if err := LockFolder(key, folder); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash during unlock "decrypting" phase:
	// some plaintext files were partially written
	_ = os.WriteFile(filepath.Join(folder, "file1.txt"), []byte("partial"), 0600)
	_ = os.MkdirAll(filepath.Join(folder, "sub"), 0700)
	_ = os.WriteFile(filepath.Join(folder, "sub", "nested.txt"), []byte("partial"), 0600)

	journal := &JournalState{
		Operation: "unlock",
		Folder:    folder,
		State:     "decrypting",
		Timestamp: time.Now(),
	}
	_ = writeJournal(folder, journal)

	err := RecoverFromJournal(folder)
	if err != nil {
		t.Fatal(err)
	}

	// Partial plaintext files should be removed
	if _, err := os.Stat(filepath.Join(folder, "file1.txt")); !os.IsNotExist(err) {
		t.Error("partial plaintext file1.txt should be removed during recovery")
	}
	if _, err := os.Stat(filepath.Join(folder, "sub", "nested.txt")); !os.IsNotExist(err) {
		t.Error("partial plaintext nested.txt should be removed during recovery")
	}

	// Journal should be cleaned up
	if _, err := os.Stat(journalPath(folder)); !os.IsNotExist(err) {
		t.Error("journal should be removed after recovery")
	}

	// Encrypted data should still be intact — can still unlock
	if !IsLocked(folder) {
		t.Error("vault should still be locked after recovery")
	}

	if err := UnlockFolder(key, folder); err != nil {
		t.Fatalf("should still unlock after recovery: %v", err)
	}

	// Verify actual content is recovered
	data, _ := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if string(data) != "hello" {
		t.Errorf("file1.txt: got %q, want %q", data, "hello")
	}
}

func TestRecoverFileFromJournalDecryptingCleansPartialFile(t *testing.T) {
	path := createTestFile(t)
	key := makeTestKey()

	// Lock the file
	if err := LockFile(key, path); err != nil {
		t.Fatal(err)
	}

	// Simulate crash during unlock: partial plaintext written
	_ = os.WriteFile(path, []byte("partial decrypt"), 0600)

	vaultDir := fileVaultDir(path)
	journal := &JournalState{
		Operation: "unlock",
		Folder:    path,
		State:     "decrypting",
		Timestamp: time.Now(),
	}
	_ = writeJournal(vaultDir, journal)

	if err := RecoverFileFromJournal(path); err != nil {
		t.Fatal(err)
	}

	// Partial plaintext should be removed
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("partial plaintext file should be removed during recovery")
	}

	// Encrypted vault should still be intact
	if !IsFileLocked(path) {
		t.Error("file should still be locked after recovery")
	}

	// Should unlock cleanly
	if err := UnlockFile(key, path); err != nil {
		t.Fatalf("should unlock after recovery: %v", err)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "secret content" {
		t.Errorf("content: got %q, want %q", data, "secret content")
	}
}

func TestRemovePartialDecrypts(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "vault")
	_ = os.MkdirAll(folder, 0700)

	// Set up monban metadata that should be preserved
	_ = os.MkdirAll(filepath.Join(folder, ".monban-data"), 0700)
	_ = os.WriteFile(filepath.Join(folder, ".monban-data", "abc.enc"), []byte("enc"), 0600)
	_ = os.WriteFile(filepath.Join(folder, ".monban-manifest.enc"), []byte("manifest"), 0600)
	_ = os.WriteFile(filepath.Join(folder, ".monban-journal.json"), []byte("{}"), 0600)

	// Add partial plaintext files that should be removed
	_ = os.WriteFile(filepath.Join(folder, "partial1.txt"), []byte("junk"), 0600)
	_ = os.MkdirAll(filepath.Join(folder, "subdir"), 0700)
	_ = os.WriteFile(filepath.Join(folder, "subdir", "partial2.txt"), []byte("junk"), 0600)

	removePartialDecrypts(folder)

	// Monban files should still exist
	if _, err := os.Stat(filepath.Join(folder, ".monban-data", "abc.enc")); err != nil {
		t.Error(".monban-data should be preserved")
	}
	if _, err := os.Stat(filepath.Join(folder, ".monban-manifest.enc")); err != nil {
		t.Error("manifest should be preserved")
	}
	if _, err := os.Stat(filepath.Join(folder, ".monban-journal.json")); err != nil {
		t.Error("journal should be preserved")
	}

	// Partial plaintext should be gone
	if _, err := os.Stat(filepath.Join(folder, "partial1.txt")); !os.IsNotExist(err) {
		t.Error("partial1.txt should be removed")
	}
	if _, err := os.Stat(filepath.Join(folder, "subdir", "partial2.txt")); !os.IsNotExist(err) {
		t.Error("partial2.txt should be removed")
	}
}
