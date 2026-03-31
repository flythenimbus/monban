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
	os.MkdirAll(folder, 0700)
	os.MkdirAll(filepath.Join(folder, "sub"), 0700)
	os.WriteFile(filepath.Join(folder, "file1.txt"), []byte("hello"), 0600)
	os.WriteFile(filepath.Join(folder, "file2.txt"), []byte("world"), 0600)
	os.WriteFile(filepath.Join(folder, "sub", "nested.txt"), []byte("nested content"), 0600)
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
	LockFolder(key, folder)
	UnlockFolder(key, folder)

	// Add a new file
	os.WriteFile(filepath.Join(folder, "new.txt"), []byte("new file"), 0600)

	// Second lock — should encrypt new file, reuse existing .enc for unchanged
	if err := LockFolder(key, folder); err != nil {
		t.Fatalf("incremental lock failed: %v", err)
	}

	// Unlock and verify all files present
	UnlockFolder(key, folder)

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
	LockFolder(key, folder)
	UnlockFolder(key, folder)

	// Modify a file (change content and ensure mod time differs)
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(filepath.Join(folder, "file1.txt"), []byte("modified!"), 0600)

	// Re-lock
	if err := LockFolder(key, folder); err != nil {
		t.Fatalf("lock after modify failed: %v", err)
	}

	// Unlock and verify modification persisted
	UnlockFolder(key, folder)

	data, _ := os.ReadFile(filepath.Join(folder, "file1.txt"))
	if string(data) != "modified!" {
		t.Errorf("file1.txt: got %q, want %q", data, "modified!")
	}
}

func TestLockDeletedFile(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	// First lock
	LockFolder(key, folder)
	UnlockFolder(key, folder)

	// Delete a file
	os.Remove(filepath.Join(folder, "file2.txt"))

	// Re-lock — stale .enc should be cleaned up
	if err := LockFolder(key, folder); err != nil {
		t.Fatalf("lock after delete failed: %v", err)
	}

	// Unlock — file2.txt should not exist
	UnlockFolder(key, folder)

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
	os.MkdirAll(filepath.Join(folder, ".monban-data"), 0700)
	os.WriteFile(filepath.Join(folder, ".monban-data", "partial.enc"), []byte("junk"), 0600)

	journal := &JournalState{
		Operation: "lock",
		Folder:    folder,
		State:     "encrypting",
		Timestamp: time.Now(),
	}
	writeJournal(folder, journal)

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
	LockFolder(key, folder)

	// Now simulate crash during "removing-originals" — journal says removing but
	// some originals might still be around (shouldn't matter, they're already encrypted)
	journal := &JournalState{
		Operation: "lock",
		Folder:    folder,
		State:     "removing-originals",
		Timestamp: time.Now(),
	}
	writeJournal(folder, journal)

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
	LockFolder(key, folder)
	// Decrypt files manually so they exist
	manifest, _ := loadEncryptedManifest(key, folder)
	decryptFilesInPlace(key, manifest, folder)

	// Simulate crash during "removing-encrypted"
	journal := &JournalState{
		Operation: "unlock",
		Folder:    folder,
		State:     "removing-encrypted",
		Timestamp: time.Now(),
	}
	writeJournal(folder, journal)

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

	LockFolder(rightKey, folder)

	err := UnlockFolder(wrongKey, folder)
	if err == nil {
		t.Error("unlock with wrong key should fail")
	}
}

func TestLockEmptyFolder(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "empty")
	os.MkdirAll(folder, 0700)
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
	os.MkdirAll(folder, 0700)
	os.WriteFile(filepath.Join(folder, "exec.sh"), []byte("#!/bin/sh"), 0755)
	os.WriteFile(filepath.Join(folder, "readonly.txt"), []byte("ro"), 0444)

	key := makeTestKey()
	LockFolder(key, folder)
	UnlockFolder(key, folder)

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
	os.WriteFile(filepath.Join(dir, "a.txt"), bytes.Repeat([]byte("x"), 1000), 0600)
	os.WriteFile(filepath.Join(dir, "b.txt"), bytes.Repeat([]byte("y"), 500), 0600)

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
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0600)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0600)
	os.MkdirAll(filepath.Join(dir, "sub"), 0700)
	os.WriteFile(filepath.Join(dir, "sub", "c.txt"), []byte("c"), 0600)

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
	os.WriteFile(path, []byte("secret content"), 0644)
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
	os.WriteFile(path, []byte("#!/bin/sh\necho hi"), 0755)

	key := makeTestKey()
	LockFile(key, path)
	UnlockFile(key, path)

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
	os.Chtimes(path, fixedTime, fixedTime)

	key := makeTestKey()
	LockFile(key, path)
	UnlockFile(key, path)

	info, _ := os.Stat(path)
	if !info.ModTime().Equal(fixedTime) {
		t.Errorf("modTime: got %v, want %v", info.ModTime(), fixedTime)
	}
}

func TestLockFileWrongKey(t *testing.T) {
	path := createTestFile(t)
	rightKey := makeTestKey()
	wrongKey := bytes.Repeat([]byte{0x99}, 32)

	LockFile(rightKey, path)

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
	os.MkdirAll(vaultDir, 0700)
	os.WriteFile(filepath.Join(vaultDir, "data.enc"), []byte("partial"), 0600)

	journal := &JournalState{
		Operation: "lock",
		Folder:    path,
		State:     "encrypting",
		Timestamp: time.Now(),
	}
	writeJournal(vaultDir, journal)

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
	LockFile(key, path)
	vaultDir := fileVaultDir(path)
	DecryptFile(key, filepath.Join(vaultDir, "data.enc"), path)

	journal := &JournalState{
		Operation: "unlock",
		Folder:    path,
		State:     "removing-encrypted",
		Timestamp: time.Now(),
	}
	writeJournal(vaultDir, journal)

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
	os.WriteFile(path, content, 0600)

	key := makeTestKey()
	LockFile(key, path)
	UnlockFile(key, path)

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

func TestCollectFilesSkipsMonbanFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "real.txt"), []byte("keep"), 0600)
	os.WriteFile(filepath.Join(dir, ".monban-journal.json"), []byte("{}"), 0600)
	os.WriteFile(filepath.Join(dir, ".monban-manifest.enc"), []byte("enc"), 0600)
	os.MkdirAll(filepath.Join(dir, ".monban-data"), 0700)
	os.WriteFile(filepath.Join(dir, ".monban-data", "a.enc"), []byte("enc"), 0600)

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
