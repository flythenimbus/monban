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
// reuse their existing .enc from the previous lock.
func encryptFilesIncremental(encKey []byte, files []fileInfo, folderPath string, prev map[string]ManifestEntry) (*Manifest, error) {
	manifest := &Manifest{Version: 1, Files: make([]ManifestEntry, len(files))}
	err := parallelOp(files, func(idx int, fi fileInfo) error {
		encName := hashedEncName(fi.relPath)

		if prev != nil {
			if prevEntry, ok := prev[fi.relPath]; ok && fileUnchanged(fi, prevEntry) {
				manifest.Files[idx] = prevEntry
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
// Manifest paths are validated to prevent path traversal attacks.
func decryptFilesInPlace(encKey []byte, manifest *Manifest, folderPath string) error {
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
		return nil
	})
}

// parallelOp runs fn over items concurrently with up to runtime.NumCPU() workers.
// Returns the first error encountered; in-flight workers skip their work once
// an error is recorded. Parallelism only (no ordering guarantees), though fn
// receives the original slice index.
func parallelOp[T any](items []T, fn func(idx int, item T) error) error {
	var firstErr atomic.Value
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())

	for i, it := range items {
		wg.Add(1)
		go func(idx int, item T) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if firstErr.Load() != nil {
				return
			}
			if err := fn(idx, item); err != nil {
				firstErr.Store(err)
			}
		}(i, it)
	}
	wg.Wait()

	if v := firstErr.Load(); v != nil {
		return v.(error)
	}
	return nil
}

// validateManifestPath checks that a manifest entry path is safe: no absolute
// paths, no ".." traversal, and the resolved path stays within the vault root.
func validateManifestPath(relPath string, cleanRoot string) error {
	if filepath.IsAbs(relPath) {
		return fmt.Errorf("absolute path not allowed")
	}
	if strings.Contains(relPath, "..") {
		return fmt.Errorf("path traversal not allowed")
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
