package monban

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
// Uses a write-ahead journal for crash safety. The optional progress callback
// is invoked once per processed file with the file's plaintext size.
func LockFolder(encKey []byte, folderPath string, progress ProgressFunc) error {
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

	manifest, err := encryptFilesIncremental(encKey, files, folderPath, prevEntries, progress)
	if err != nil {
		return err
	}

	// Remove .enc files for files that no longer exist
	cleanupStaleEncFiles(manifest, prevEntries, folderPath)

	if err := writeEncryptedManifest(encKey, folderPath, manifest); err != nil {
		return err
	}

	// Durability gate: fsync every .enc and the data directory before
	// originals are deleted. EncryptFile no longer fsyncs per file —
	// chunked syncs in encryptFilesIncremental + this final sweep
	// give the same crash-safety guarantee at a fraction of the cost.
	fsyncDataDir(folderPath)

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
// The optional progress callback is invoked once per processed file with
// the file's plaintext size.
func UnlockFolder(encKey []byte, folderPath string, progress ProgressFunc) error {
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

	if err := decryptFilesInPlace(encKey, manifest, folderPath, progress); err != nil {
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
// The original file is deleted after encryption. The optional progress
// callback is invoked once with the file's plaintext size.
func LockFile(encKey []byte, filePath string, progress ProgressFunc) error {
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

	// Durability gate: fsync the .enc before deleting the plaintext.
	// EncryptFile no longer fsyncs per file (chunked sync handled by
	// LockFolder); single-file vaults handle their own sync here.
	_ = fsyncPath(encPath)

	journal.State = "removing-originals"
	if err := writeJournal(vaultDir, journal); err != nil {
		return fmt.Errorf("updating journal: %w", err)
	}

	_ = os.Remove(filePath)
	if progress != nil {
		progress(info.Size())
	}

	journal.State = "complete"
	_ = writeJournal(vaultDir, journal)
	removeJournal(vaultDir)

	return nil
}

// UnlockFile decrypts a single file from its vault directory.
// The optional progress callback is invoked once with the file's plaintext size.
func UnlockFile(encKey []byte, filePath string, progress ProgressFunc) error {
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

	if progress != nil {
		progress(entry.Size)
	}
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

// FolderStats walks path once and returns total file count and total bytes,
// skipping monban metadata files and the .monban-data directory. Used by
// progress reporting to compute totals before encryption begins.
func FolderStats(path string) (files int64, bytes int64, err error) {
	err = filepath.Walk(path, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if info.Name() == ".monban-data" {
				return filepath.SkipDir
			}
			return nil
		}
		name := info.Name()
		if name == ".monban-journal.json" || name == ".monban-manifest.enc" {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		files++
		bytes += info.Size()
		return nil
	})
	return files, bytes, err
}

// ManifestStats returns file count and total plaintext bytes of the
// encrypted manifest at folderPath. Used for unlock progress totals.
// encKey may be nil or wrong — the result is (0, 0, err) in that case.
func ManifestStats(encKey []byte, folderPath string) (files int64, bytes int64, err error) {
	manifest, err := loadEncryptedManifest(encKey, folderPath)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range manifest.Files {
		files++
		bytes += e.Size
	}
	return files, bytes, nil
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

