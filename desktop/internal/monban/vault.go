package monban

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// --- Types ---

// JournalState tracks the progress of a lock/unlock operation for crash recovery.
type JournalState struct {
	Operation string    `json:"operation"` // "lock" or "unlock"
	Folder    string    `json:"folder"`    // protected folder path
	State     string    `json:"state"`     // "encrypting", "removing-originals", "decrypting", "removing-encrypted", "complete"
	Timestamp time.Time `json:"timestamp"`
}

// ManifestEntry represents a single file in the vault manifest.
type ManifestEntry struct {
	Path    string      `json:"path"`     // relative path within the folder (original name)
	EncName string      `json:"enc_name"` // hashed filename in .monban-data/
	Size    int64       `json:"size"`
	Mode    os.FileMode `json:"mode"`
	ModTime time.Time   `json:"mod_time"`
}

// Manifest tracks all encrypted files in a vault.
type Manifest struct {
	Version int             `json:"version"`
	Files   []ManifestEntry `json:"files"`
}

// --- Public functions ---

// LockFolder encrypts all files in folderPath into .monban-data/ with hashed names.
// New and modified files are encrypted; unchanged files reuse their existing .enc.
// Deleted files have their .enc removed. Originals are removed after encryption.
// Uses a write-ahead journal for crash safety.
func LockFolder(encKey []byte, folderPath string) error {
	if err := os.MkdirAll(dataDir(folderPath), 0700); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	journal := &JournalState{
		Operation: "lock",
		Folder:    folderPath,
		State:     "encrypting",
		Timestamp: time.Now(),
	}
	if err := writeJournal(folderPath, journal); err != nil {
		return fmt.Errorf("writing journal: %w", err)
	}

	// Load previous manifest to detect unchanged files
	prevEntries := loadPreviousManifest(encKey, folderPath)

	files, err := collectFiles(folderPath)
	if err != nil {
		return fmt.Errorf("collecting files: %w", err)
	}

	manifest, err := encryptFilesIncremental(encKey, files, folderPath, prevEntries)
	if err != nil {
		return err
	}

	// Remove .enc files for files that no longer exist
	cleanupStaleEncFiles(manifest, prevEntries, folderPath)

	if err := writeEncryptedManifest(encKey, folderPath, manifest); err != nil {
		return err
	}

	journal.State = "removing-originals"
	if err := writeJournal(folderPath, journal); err != nil {
		return fmt.Errorf("updating journal: %w", err)
	}

	removeOriginals(files, folderPath)

	journal.State = "complete"
	_ = writeJournal(folderPath, journal)
	removeJournal(folderPath)

	return nil
}

// UnlockFolder decrypts all .enc files in folderPath back to their originals.
func UnlockFolder(encKey []byte, folderPath string) error {
	manifest, err := loadEncryptedManifest(encKey, folderPath)
	if err != nil {
		return err
	}

	journal := &JournalState{
		Operation: "unlock",
		Folder:    folderPath,
		State:     "decrypting",
		Timestamp: time.Now(),
	}
	if err := writeJournal(folderPath, journal); err != nil {
		return fmt.Errorf("writing journal: %w", err)
	}

	if err := decryptFilesInPlace(encKey, manifest, folderPath); err != nil {
		return err
	}

	journal.State = "removing-encrypted"
	if err := writeJournal(folderPath, journal); err != nil {
		return fmt.Errorf("updating journal: %w", err)
	}

	removeEncryptedData(folderPath)
	_ = os.Remove(manifestPath(folderPath))

	journal.State = "complete"
	_ = writeJournal(folderPath, journal)
	removeJournal(folderPath)

	return nil
}

// RecoverFromJournal checks for an interrupted lock/unlock and recovers.
func RecoverFromJournal(folderPath string) error {
	journal, err := readJournal(folderPath)
	if err != nil {
		return nil
	}

	switch journal.Operation {
	case "lock":
		switch journal.State {
		case "encrypting":
			// Originals intact, remove partial encrypted data
			removeEncryptedData(folderPath)
			_ = os.Remove(manifestPath(folderPath))
		case "removing-originals":
			// All encrypted, some originals may remain — that's fine
		}
	case "unlock":
		switch journal.State {
		case "decrypting":
			// Encrypted data is intact in .monban-data/. Remove any
			// partially-decrypted plaintext files so the vault is left
			// in a clean locked state for the user to re-trigger unlock.
			removePartialDecrypts(folderPath)
		case "removing-encrypted":
			// Decrypted files written, resume cleanup
			removeEncryptedData(folderPath)
			_ = os.Remove(manifestPath(folderPath))
		}
	}

	removeJournal(folderPath)
	return nil
}

// IsLocked checks if a folder has an encrypted manifest (meaning it's locked).
func IsLocked(folderPath string) bool {
	_, err := os.Stat(manifestPath(folderPath))
	return err == nil
}

// --- Single file vault ---
//
// When a single file is locked, it is stored in an opaque directory next to the
// original, with the filename scrambled. On disk:
//
//   /path/to/.monban-<hash16>/
//     data.enc                  — encrypted file content
//     .monban-manifest.enc      — encrypted manifest (original name, perms, modtime)
//     .monban-journal.json      — write-ahead journal (transient)
//   /path/to/secret.txt         — deleted
//
// The <hash16> is the first 16 hex chars of SHA-256(absolute file path).

// IsFileLocked checks if a single file has a locked vault directory.
func IsFileLocked(filePath string) bool {
	_, err := os.Stat(filepath.Join(fileVaultDir(filePath), ".monban-manifest.enc"))
	return err == nil
}

// LockFile encrypts a single file into an opaque vault directory.
// The original file is deleted after encryption.
func LockFile(encKey []byte, filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}

	vaultDir := fileVaultDir(filePath)
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return fmt.Errorf("creating vault dir: %w", err)
	}

	journal := &JournalState{
		Operation: "lock",
		Folder:    filePath,
		State:     "encrypting",
		Timestamp: time.Now(),
	}
	if err := writeJournal(vaultDir, journal); err != nil {
		return fmt.Errorf("writing journal: %w", err)
	}

	encPath := filepath.Join(vaultDir, "data.enc")
	if err := EncryptFile(encKey, filePath, encPath); err != nil {
		return fmt.Errorf("encrypting file: %w", err)
	}

	// Write encrypted manifest with original file metadata
	manifest := &Manifest{
		Version: 1,
		Files: []ManifestEntry{{
			Path:    filepath.Base(filePath),
			EncName: "data.enc",
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
		}},
	}
	if err := writeEncryptedManifest(encKey, vaultDir, manifest); err != nil {
		_ = os.Remove(encPath)
		return fmt.Errorf("writing manifest: %w", err)
	}

	journal.State = "removing-originals"
	if err := writeJournal(vaultDir, journal); err != nil {
		return fmt.Errorf("updating journal: %w", err)
	}

	_ = os.Remove(filePath)

	journal.State = "complete"
	_ = writeJournal(vaultDir, journal)
	removeJournal(vaultDir)

	return nil
}

// UnlockFile decrypts a single file from its vault directory.
func UnlockFile(encKey []byte, filePath string) error {
	vaultDir := fileVaultDir(filePath)

	manifest, err := loadEncryptedManifest(encKey, vaultDir)
	if err != nil {
		return fmt.Errorf("loading manifest: %w", err)
	}
	if len(manifest.Files) == 0 {
		return fmt.Errorf("empty manifest")
	}
	entry := manifest.Files[0]

	journal := &JournalState{
		Operation: "unlock",
		Folder:    filePath,
		State:     "decrypting",
		Timestamp: time.Now(),
	}
	if err := writeJournal(vaultDir, journal); err != nil {
		return fmt.Errorf("writing journal: %w", err)
	}

	encPath := filepath.Join(vaultDir, entry.EncName)
	if err := DecryptFile(encKey, encPath, filePath); err != nil {
		return fmt.Errorf("decrypting file: %w", err)
	}

	_ = os.Chmod(filePath, entry.Mode)
	_ = os.Chtimes(filePath, entry.ModTime, entry.ModTime)

	journal.State = "removing-encrypted"
	if err := writeJournal(vaultDir, journal); err != nil {
		return fmt.Errorf("updating journal: %w", err)
	}

	_ = os.RemoveAll(vaultDir)

	return nil
}

// RecoverFileFromJournal checks for an interrupted file lock/unlock and recovers.
func RecoverFileFromJournal(filePath string) error {
	vaultDir := fileVaultDir(filePath)
	journal, err := readJournal(vaultDir)
	if err != nil {
		return nil // no journal
	}

	switch journal.Operation {
	case "lock":
		switch journal.State {
		case "encrypting":
			// Original intact, remove partial vault dir
			_ = os.RemoveAll(vaultDir)
		case "removing-originals":
			// Encrypted data written, original may or may not exist — fine
		}
	case "unlock":
		switch journal.State {
		case "decrypting":
			// Encrypted data intact in vault dir. Remove the partially
			// decrypted file so the vault stays in a clean locked state.
			_ = os.Remove(filePath)
		case "removing-encrypted":
			// Decrypted file written, resume cleanup
			_ = os.RemoveAll(vaultDir)
		}
	}

	removeJournal(vaultDir)
	return nil
}

// FolderSize returns the size of a directory in bytes.
func FolderSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// FreeSpace returns available bytes on the volume containing path.
func FreeSpace(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, fmt.Errorf("statfs: %w", err)
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

// CountFiles counts non-directory files under path.
func CountFiles(path string) (int, error) {
	count := 0
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			count++
		}
		return nil
	})
	return count, err
}

// FormatBytes formats bytes as a human-readable string.
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return strconv.FormatInt(b, 10) + " B"
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return strings.TrimRight(strings.TrimRight(
		strconv.FormatFloat(float64(b)/float64(div), 'f', 1, 64), "0"), ".") +
		" " + string([]byte("KMGTPE")[exp]) + "B"
}

// --- Private types and helpers ---

const encSuffix = ".enc"

type fileInfo struct {
	absPath string
	relPath string
	size    int64
	mode    os.FileMode
	modTime time.Time
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
	var encErr atomic.Value
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())

	for i, f := range files {
		wg.Add(1)
		go func(idx int, fi fileInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if encErr.Load() != nil {
				return
			}

			encName := hashedEncName(fi.relPath)

			// Check if file is unchanged from previous lock
			if prev != nil {
				if prevEntry, ok := prev[fi.relPath]; ok && fileUnchanged(fi, prevEntry) {
					// Reuse existing .enc — no need to re-encrypt
					manifest.Files[idx] = prevEntry
					return
				}
			}

			encPath := filepath.Join(dataDir(folderPath), encName)

			if err := EncryptFile(encKey, fi.absPath, encPath); err != nil {
				encErr.Store(fmt.Errorf("encrypting %s: %w", fi.relPath, err))
				return
			}

			manifest.Files[idx] = ManifestEntry{
				Path:    fi.relPath,
				EncName: encName,
				Size:    fi.size,
				Mode:    fi.mode,
				ModTime: fi.modTime,
			}
		}(i, f)
	}
	wg.Wait()

	if v := encErr.Load(); v != nil {
		return nil, v.(error)
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
	// Pre-validate all manifest paths before any decryption
	cleanRoot := filepath.Clean(folderPath)
	for _, e := range manifest.Files {
		if err := validateManifestPath(e.Path, cleanRoot); err != nil {
			return fmt.Errorf("unsafe manifest entry %q: %w", e.Path, err)
		}
	}

	var decErr atomic.Value
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())

	for _, entry := range manifest.Files {
		wg.Add(1)
		go func(e ManifestEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if decErr.Load() != nil {
				return
			}

			encPath := filepath.Join(dataDir(folderPath), e.EncName)
			dstPath := filepath.Join(cleanRoot, e.Path)

			if err := os.MkdirAll(filepath.Dir(dstPath), 0700); err != nil {
				decErr.Store(fmt.Errorf("creating dir for %s: %w", e.Path, err))
				return
			}

			if err := DecryptFile(encKey, encPath, dstPath); err != nil {
				decErr.Store(fmt.Errorf("decrypting %s: %w", e.Path, err))
				return
			}

			_ = os.Chmod(dstPath, e.Mode)
			_ = os.Chtimes(dstPath, e.ModTime, e.ModTime)
		}(entry)
	}
	wg.Wait()

	if v := decErr.Load(); v != nil {
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
