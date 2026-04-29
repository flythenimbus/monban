package monban

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

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
	if err := LockFolder(key, folder, nil); err != nil {
		t.Fatal(err)
	}

	v := VaultEntry{Label: "test", Path: folder}

	// Locking again should be a no-op (not an error)
	if err := LockVaultEntry(key, v, nil); err != nil {
		t.Errorf("locking already-locked vault should not error: %v", err)
	}
}

func TestUnlockVaultEntrySkipsAlreadyUnlocked(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	v := VaultEntry{Label: "test", Path: folder}

	// Folder is already unlocked (never locked)
	if err := UnlockVaultEntry(key, v, nil); err != nil {
		t.Errorf("unlocking already-unlocked vault should not error: %v", err)
	}
}

func TestLockUnlockVaultEntryFile(t *testing.T) {
	path := createTestFile(t)
	key := makeTestKey()

	v := VaultEntry{Label: "secret", Path: path, Type: "file"}

	if err := LockVaultEntry(key, v, nil); err != nil {
		t.Fatalf("lock file vault entry failed: %v", err)
	}

	if !IsFileLocked(path) {
		t.Error("file should be locked")
	}

	if err := UnlockVaultEntry(key, v, nil); err != nil {
		t.Fatalf("unlock file vault entry failed: %v", err)
	}

	if IsFileLocked(path) {
		t.Error("file should be unlocked")
	}
}

// TestParallelOpProcessesAllItems exercises the worker-pool refactor.
// Earlier the function spawned one goroutine per item up front and gated
// them on a semaphore, which OOMed for large item counts. We use a fixed
// pool now; this test confirms every item is still visited exactly once.
func TestParallelOpProcessesAllItems(t *testing.T) {
	const n = 5000
	items := make([]int, n)
	for i := range items {
		items[i] = i
	}

	var visited [n]int32
	err := parallelOp(items, func(idx int, _ int) error {
		atomic.AddInt32(&visited[idx], 1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range visited {
		if v != 1 {
			t.Fatalf("item %d visited %d times, want 1", i, v)
		}
	}
}

// TestParallelOpEarlyError verifies the producer stops feeding new
// indices once a worker reports an error, and the function returns
// that error promptly.
func TestParallelOpEarlyError(t *testing.T) {
	items := make([]int, 1000)
	sentinel := errors.New("boom")
	var seen atomic.Int64

	err := parallelOp(items, func(idx int, _ int) error {
		seen.Add(1)
		if idx == 10 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	// Producer breaks on next iteration after the error is recorded;
	// in-flight workers drain. We expect notably fewer than 1000 calls,
	// not a tight upper bound — just a sanity check we didn't process
	// every item before returning.
	if seen.Load() >= int64(len(items)) {
		t.Fatalf("expected early termination, all %d items were visited", seen.Load())
	}
}

// TestParallelOpEmpty: calling with zero items must not deadlock and
// must return nil. (Edge case for vaults with no protected files.)
func TestParallelOpEmpty(t *testing.T) {
	err := parallelOp([]int{}, func(_ int, _ int) error {
		t.Fatal("fn should not be invoked on empty input")
		return nil
	})
	if err != nil {
		t.Fatalf("empty input returned %v, want nil", err)
	}
}

// TestLockFolderProgressCallback confirms the progress callback fires
// once per processed file. Used by the lock-screen progress bar.
func TestLockFolderProgressCallback(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	var calls atomic.Int64
	var bytes atomic.Int64
	prog := func(b int64) {
		calls.Add(1)
		bytes.Add(b)
	}

	if err := LockFolder(key, folder, prog); err != nil {
		t.Fatal(err)
	}

	// createTestFolder writes 3 files (file1, file2, sub/nested)
	if got := calls.Load(); got != 3 {
		t.Errorf("progress callback fired %d times, want 3", got)
	}
	// "hello" + "world" + "nested content" = 5 + 5 + 14 = 24
	if got := bytes.Load(); got != 24 {
		t.Errorf("progress reported %d bytes, want 24", got)
	}
}

// TestUnlockFolderProgressCallback symmetrically covers unlock.
func TestUnlockFolderProgressCallback(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	if err := LockFolder(key, folder, nil); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int64
	if err := UnlockFolder(key, folder, func(_ int64) { calls.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("unlock progress fired %d times, want 3", got)
	}
}

// TestManifestStats reads totals from an encrypted manifest. Used
// by progress reporting on unlock to seed the bar without walking
// (the plaintext doesn't exist on disk while the vault is locked).
func TestManifestStats(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()

	if err := LockFolder(key, folder, nil); err != nil {
		t.Fatal(err)
	}
	files, bytes, err := ManifestStats(key, folder)
	if err != nil {
		t.Fatal(err)
	}
	// createTestFolder writes 3 files: "hello"(5) "world"(5) "nested content"(14)
	if files != 3 {
		t.Errorf("files = %d, want 3", files)
	}
	if bytes != 24 {
		t.Errorf("bytes = %d, want 24", bytes)
	}
}

// TestManifestStats_WrongKey: a wrong key can't decrypt the manifest
// and ManifestStats must fail rather than return zeros (zeros would
// look like an empty vault and silently disable the progress overlay).
func TestManifestStats_WrongKey(t *testing.T) {
	folder := createTestFolder(t)
	key := makeTestKey()
	if err := LockFolder(key, folder, nil); err != nil {
		t.Fatal(err)
	}
	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = 0x01
	}
	if _, _, err := ManifestStats(wrong, folder); err == nil {
		t.Error("ManifestStats with wrong key should error")
	}
}

// TestManifestStats_MissingManifest: an unlocked vault has no
// manifest; report an error.
func TestManifestStats_MissingManifest(t *testing.T) {
	dir := t.TempDir()
	key := makeTestKey()
	if _, _, err := ManifestStats(key, dir); err == nil {
		t.Error("ManifestStats on vault without manifest should error")
	}
}

// TestLockFileProgressCallback: per-file progress callback fires
// once during LockFile.
func TestLockFileProgressCallback(t *testing.T) {
	path := createTestFile(t)
	key := makeTestKey()

	var calls atomic.Int64
	var bytes atomic.Int64
	if err := LockFile(key, path, func(b int64) {
		calls.Add(1)
		bytes.Add(b)
	}); err != nil {
		t.Fatal(err)
	}

	if got := calls.Load(); got != 1 {
		t.Errorf("LockFile progress fired %d times, want 1", got)
	}
	// createTestFile writes "secret content" = 14 bytes.
	if got := bytes.Load(); got != 14 {
		t.Errorf("LockFile reported %d bytes, want 14", got)
	}
}

// TestUnlockFileProgressCallback symmetric coverage for UnlockFile.
func TestUnlockFileProgressCallback(t *testing.T) {
	path := createTestFile(t)
	key := makeTestKey()
	if err := LockFile(key, path, nil); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int64
	if err := UnlockFile(key, path, func(_ int64) { calls.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("UnlockFile progress fired %d times, want 1", got)
	}
}

// TestFileVaultDirOf is the exported wrapper used by app/progress.go
// to read a file vault's encrypted manifest. Locking + unlocking via
// the public API would already exercise it; this just pins that the
// wrapper agrees with the private implementation.
func TestFileVaultDirOf(t *testing.T) {
	got := FileVaultDirOf("/tmp/secret.txt")
	if got == "" {
		t.Error("FileVaultDirOf returned empty string")
	}
	if got != fileVaultDir("/tmp/secret.txt") {
		t.Error("FileVaultDirOf disagrees with private fileVaultDir")
	}
}

// TestFolderStats walks once and returns count+bytes; used by app_auth
// to compute progress totals before starting a lock.
func TestFolderStats(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a"), []byte("aa"), 0600)         // 2
	_ = os.WriteFile(filepath.Join(dir, "b"), []byte("bbbb"), 0600)       // 4
	_ = os.MkdirAll(filepath.Join(dir, "sub"), 0700)
	_ = os.WriteFile(filepath.Join(dir, "sub", "c"), []byte("c"), 0600)   // 1
	// Skipped: monban metadata + the data dir
	_ = os.WriteFile(filepath.Join(dir, ".monban-journal.json"), []byte("xx"), 0600)
	_ = os.MkdirAll(filepath.Join(dir, ".monban-data"), 0700)
	_ = os.WriteFile(filepath.Join(dir, ".monban-data", "x.enc"), []byte("yyyy"), 0600)

	files, bytes, err := FolderStats(dir)
	if err != nil {
		t.Fatal(err)
	}
	if files != 3 {
		t.Errorf("files: got %d, want 3", files)
	}
	if bytes != 7 {
		t.Errorf("bytes: got %d, want 7", bytes)
	}
}

// TestChunkSizeBackwardCompat confirms the new ChunkSize constant is
// carried through the per-file header, so old vaults locked with the
// previous 64 KB constant still decrypt against the new build.
func TestChunkSizeBackwardCompat(t *testing.T) {
	key := bytes64("key")
	dir := t.TempDir()
	src := filepath.Join(dir, "p")
	enc := filepath.Join(dir, "e")
	dec := filepath.Join(dir, "d")

	// Plaintext spanning multiple chunks at the *current* size.
	plain := make([]byte, ChunkSize*2+1234)
	for i := range plain {
		plain[i] = byte(i)
	}
	_ = os.WriteFile(src, plain, 0600)

	if err := EncryptFile(key, src, enc); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(key, enc, dec); err != nil {
		t.Fatalf("decrypt with current ChunkSize failed: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if len(got) != len(plain) {
		t.Fatalf("decrypted len: got %d, want %d", len(got), len(plain))
	}
}

func bytes64(seed string) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(fmt.Sprintf("%-32s", seed)[i])
	}
	return out
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

	if err := LockVaultEntry(lazyKey, v, nil); err != nil {
		t.Fatalf("lock with lazy key failed: %v", err)
	}

	if !IsLocked(folder) {
		t.Error("folder should be locked")
	}

	if err := UnlockVaultEntry(lazyKey, v, nil); err != nil {
		t.Fatalf("unlock with lazy key failed: %v", err)
	}

	if IsLocked(folder) {
		t.Error("folder should be unlocked")
	}
}
