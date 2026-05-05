package monban

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProgressFunc reports per-file completion during lock/unlock. The callback
// is invoked once per processed file (encrypted or decrypted), with the
// file's plaintext size in bytes. May be called concurrently from multiple
// workers; implementations must be safe under that. May be nil.
type ProgressFunc func(fileBytes int64)

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

// --- Private/unexported helpers below ---

const encSuffix = ".enc"

type fileInfo struct {
	absPath string
	relPath string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func withTrailingSep(p string) string {
	if strings.HasSuffix(p, string(filepath.Separator)) {
		return p
	}
	return p + string(filepath.Separator)
}

func journalPath(folderPath string) string {
	return filepath.Join(folderPath, ".monban-journal.json")
}

func manifestPath(folderPath string) string {
	return filepath.Join(folderPath, ".monban-manifest.enc")
}

func dataDir(folderPath string) string {
	return filepath.Join(folderPath, ".monban-data")
}

func writeJournal(folderPath string, j *JournalState) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(journalPath(folderPath), data, 0600)
}

func readJournal(folderPath string) (*JournalState, error) {
	data, err := os.ReadFile(journalPath(folderPath))
	if err != nil {
		return nil, err
	}
	var j JournalState
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return &j, nil
}

func removeJournal(folderPath string) {
	_ = os.Remove(journalPath(folderPath))
}

// collectFiles walks a directory and returns metadata for every non-monban file.
// Symlinks are rejected to prevent symlink-based attacks (exfiltration, arbitrary
// file overwrite on decrypt).
func collectFiles(root string) ([]fileInfo, error) {
	var files []fileInfo
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Reject symlinks — a symlink inside a vault could point outside it,
		// allowing an attacker to exfiltrate or overwrite arbitrary files.
		if info.Mode()&os.ModeSymlink != 0 {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// Double-check with Lstat for Walk's implicit dereference
		if path != root {
			linfo, lerr := os.Lstat(path)
			if lerr != nil {
				return lerr
			}
			if linfo.Mode()&os.ModeSymlink != 0 {
				if linfo.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		// Skip .monban-data directory entirely
		if info.IsDir() && info.Name() == ".monban-data" {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		// Skip monban metadata files
		name := info.Name()
		if name == ".monban-journal.json" || name == ".monban-manifest.enc" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, fileInfo{
			absPath: path,
			relPath: rel,
			size:    info.Size(),
			mode:    info.Mode(),
			modTime: info.ModTime(),
		})
		return nil
	})
	return files, err
}

// loadPreviousManifest tries to load and decrypt the existing manifest.
// Returns a map of path → ManifestEntry for quick lookup, or nil if no manifest exists.
func loadPreviousManifest(encKey []byte, folderPath string) map[string]ManifestEntry {
	if encKey == nil {
		return nil
	}
	manifest, err := loadEncryptedManifest(encKey, folderPath)
	if err != nil {
		return nil
	}
	m := make(map[string]ManifestEntry, len(manifest.Files))
	for _, e := range manifest.Files {
		m[e.Path] = e
	}
	return m
}

// fileUnchanged checks if a file matches its previous manifest entry (same size + mod time).
func fileUnchanged(fi fileInfo, prev ManifestEntry) bool {
	return fi.size == prev.Size && fi.modTime.Equal(prev.ModTime)
}

// encryptFilesIncremental encrypts only new or modified files. Unchanged files
// reuse their existing .enc from the previous lock. progress (may be nil) is
// invoked once per processed file with the file's plaintext size.
//
// Chunked fsync: every syncEveryFiles completed encryptions, the worker
// fsyncs its just-written .enc. This spreads the durability cost across
// the run so the final pre-removeOriginals fsync sweep has less work.
// Until the originals are removed, unsynced .enc files don't represent
// data loss risk — recovery rolls back the partial state.
func encryptFilesIncremental(encKey []byte, files []fileInfo, folderPath string, prev map[string]ManifestEntry, progress ProgressFunc) (*Manifest, error) {
	manifest := &Manifest{Version: 1, Files: make([]ManifestEntry, len(files))}
	var doneCount atomic.Int64
	err := parallelOp(files, func(idx int, fi fileInfo) error {
		encName := hashedEncName(fi.relPath)

		if prev != nil {
			if prevEntry, ok := prev[fi.relPath]; ok && fileUnchanged(fi, prevEntry) {
				manifest.Files[idx] = prevEntry
				if progress != nil {
					progress(fi.size)
				}
				return nil
			}
		}

		encPath := filepath.Join(dataDir(folderPath), encName)
		if err := EncryptFile(encKey, fi.absPath, encPath); err != nil {
			return fmt.Errorf("encrypting %s: %w", fi.relPath, err)
		}

		manifest.Files[idx] = ManifestEntry{
			Path:    fi.relPath,
			EncName: encName,
			Size:    fi.size,
			Mode:    fi.mode,
			ModTime: fi.modTime,
		}

		if doneCount.Add(1)%syncEveryFiles == 0 {
			_ = fsyncPath(encPath)
		}
		if progress != nil {
			progress(fi.size)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

// cleanupStaleEncFiles removes .enc files for files that were deleted since the last lock.
func cleanupStaleEncFiles(current *Manifest, prev map[string]ManifestEntry, folderPath string) {
	if prev == nil {
		return
	}
	// Build set of current paths
	currentPaths := make(map[string]bool, len(current.Files))
	for _, e := range current.Files {
		currentPaths[e.Path] = true
	}
	// Remove .enc for any path in prev that's not in current
	for path, entry := range prev {
		if !currentPaths[path] {
			encPath := filepath.Join(dataDir(folderPath), entry.EncName)
			_ = os.Remove(encPath)
		}
	}
}

// decryptFilesInPlace decrypts files from .monban-data/ back to their original paths.
// Manifest paths are validated to prevent path traversal attacks. progress (may
// be nil) is invoked once per decrypted file with the file's plaintext size.
func decryptFilesInPlace(encKey []byte, manifest *Manifest, folderPath string, progress ProgressFunc) error {
	cleanRoot := filepath.Clean(folderPath)
	for _, e := range manifest.Files {
		if err := validateManifestPath(e.Path, cleanRoot); err != nil {
			return fmt.Errorf("unsafe manifest entry %q: %w", e.Path, err)
		}
	}

	return parallelOp(manifest.Files, func(_ int, e ManifestEntry) error {
		encPath := filepath.Join(dataDir(folderPath), e.EncName)
		dstPath := filepath.Join(cleanRoot, e.Path)

		if err := os.MkdirAll(filepath.Dir(dstPath), 0700); err != nil {
			return fmt.Errorf("creating dir for %s: %w", e.Path, err)
		}
		if err := DecryptFile(encKey, encPath, dstPath); err != nil {
			return fmt.Errorf("decrypting %s: %w", e.Path, err)
		}

		_ = os.Chmod(dstPath, e.Mode)
		_ = os.Chtimes(dstPath, e.ModTime, e.ModTime)
		if progress != nil {
			progress(e.Size)
		}
		return nil
	})
}

// syncEveryFiles is the chunked-fsync batch size. Every Nth completed
// encryption gets its .enc fsynced inside the worker, spreading the
// durability cost across the run instead of one big sweep at the end.
const syncEveryFiles = 32

// parallelOp runs fn over items concurrently with a fixed pool of
// runtime.NumCPU() workers pulling from an index channel. Earlier
// versions spawned one goroutine per item up front and gated them
// on a semaphore, which OOMed (or, on macOS, made the runtime hang
// for tens of seconds) when locking vaults containing tens of
// thousands of small files. A fixed pool keeps memory bounded.
//
// Returns the first error encountered; once an error is recorded
// the producer stops feeding new indices and in-flight workers
// drain quickly. fn receives the original slice index for ordered
// writes into a shared output slice.
func parallelOp[T any](items []T, fn func(idx int, item T) error) error {
	if len(items) == 0 {
		return nil
	}
	workers := runtime.NumCPU()
	if workers > len(items) {
		workers = len(items)
	}
	if workers < 1 {
		workers = 1
	}

	var firstErr atomic.Value
	var wg sync.WaitGroup
	indices := make(chan int, workers*2)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range indices {
				if firstErr.Load() != nil {
					continue // drain; let producer finish & close channel
				}
				if err := fn(idx, items[idx]); err != nil {
					firstErr.Store(err)
				}
			}
		}()
	}

	for i := range items {
		if firstErr.Load() != nil {
			break
		}
		indices <- i
	}
	close(indices)
	wg.Wait()

	if v := firstErr.Load(); v != nil {
		return v.(error)
	}
	return nil
}

// fsyncPath opens path read-only, fsyncs it, and closes it. Used for
// the chunked-fsync batches inside encryptFilesIncremental. Best
// effort — caller ignores errors because the final pre-removeOriginals
// sweep will retry.
func fsyncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// fsyncDataDir walks folderPath/.monban-data and fsyncs every .enc
// file plus the directory itself. Called once per LockFolder right
// before the journal advances to "removing-originals" — the durability
// gate before plaintext is deleted. Most files are already synced by
// the chunked-sync inside the encryption loop, so the final sweep is
// usually cheap.
func fsyncDataDir(folderPath string) {
	dir := dataDir(folderPath)
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		_ = fsyncPath(path)
		return nil
	})
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// validateManifestPath checks that a manifest entry path is safe: no absolute
// paths, no ".." path components, and the resolved path stays within the
// vault root.
//
// Earlier versions used strings.Contains(relPath, "..") as the traversal
// check, which produced false positives for legitimate filenames containing
// double dots — e.g. "Calgary South Inc..pdf" — and refused to decrypt
// vaults that had been locked containing such files. We now check that no
// path *component* equals "..", which is the actual escape primitive.
func validateManifestPath(relPath string, cleanRoot string) error {
	if filepath.IsAbs(relPath) {
		return fmt.Errorf("absolute path not allowed")
	}
	for _, comp := range strings.Split(filepath.ToSlash(relPath), "/") {
		if comp == ".." {
			return fmt.Errorf("path traversal not allowed")
		}
	}
	resolved := filepath.Join(cleanRoot, relPath)
	if !strings.HasPrefix(filepath.Clean(resolved), cleanRoot+string(filepath.Separator)) &&
		filepath.Clean(resolved) != cleanRoot {
		return fmt.Errorf("path escapes vault root")
	}
	return nil
}

// writeEncryptedManifest serializes the manifest to JSON and encrypts it in memory.
// No plaintext is ever written to disk.
func writeEncryptedManifest(encKey []byte, folderPath string, manifest *Manifest) error {
	data, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshalling manifest: %w", err)
	}

	encrypted, err := EncryptBytes(encKey, data)
	if err != nil {
		return fmt.Errorf("encrypting manifest: %w", err)
	}

	if err := os.WriteFile(manifestPath(folderPath), encrypted, 0600); err != nil {
		return fmt.Errorf("writing encrypted manifest: %w", err)
	}
	return nil
}

// loadEncryptedManifest reads and decrypts the manifest in memory.
// If encKey is nil, returns an error (used during recovery when key is unavailable).
func loadEncryptedManifest(encKey []byte, folderPath string) (*Manifest, error) {
	if encKey == nil {
		return nil, fmt.Errorf("no encryption key available")
	}

	encrypted, err := os.ReadFile(manifestPath(folderPath))
	if err != nil {
		return nil, fmt.Errorf("reading encrypted manifest: %w", err)
	}

	data, err := DecryptBytes(encKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypting manifest: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return &manifest, nil
}

func removeOriginals(files []fileInfo, folderPath string) {
	for _, f := range files {
		_ = os.Remove(f.absPath)
	}
	removeEmptyDirs(folderPath)
}

func removeEncryptedData(folderPath string) {
	_ = os.RemoveAll(dataDir(folderPath))
}

// removePartialDecrypts removes any non-monban files from a vault folder.
// Used during crash recovery when unlock was interrupted mid-decryption:
// encrypted data in .monban-data/ is still intact, but partial plaintext
// files may have been written. Removing them leaves the vault in a clean
// locked state so the user can re-trigger unlock.
func removePartialDecrypts(folderPath string) {
	_ = filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == ".monban-data" {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		name := info.Name()
		if name == ".monban-journal.json" || name == ".monban-manifest.enc" {
			return nil
		}
		_ = os.Remove(path)
		return nil
	})
	removeEmptyDirs(folderPath)
}

func hashedEncName(relPath string) string {
	h := sha256.Sum256([]byte(relPath))
	return hex.EncodeToString(h[:16]) + encSuffix
}

func removeEmptyDirs(root string) {
	var dirs []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, _ error) error {
		if info != nil && info.IsDir() && path != root && info.Name() != ".monban-data" {
			dirs = append(dirs, path)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Remove(dirs[i])
	}
}

// fileVaultDir returns the opaque directory path for a file vault.
func fileVaultDir(filePath string) string {
	h := sha256.Sum256([]byte(filePath))
	name := ".monban-" + hex.EncodeToString(h[:8])
	return filepath.Join(filepath.Dir(filePath), name)
}

// FileVaultDirOf is the exported variant of fileVaultDir, used by callers
// outside this package that need to read the encrypted manifest of a
// single-file vault (e.g. progress reporting computing totals).
func FileVaultDirOf(filePath string) string {
	return fileVaultDir(filePath)
}
