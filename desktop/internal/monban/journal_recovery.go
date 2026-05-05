package monban

import (
	"os"
)

// --- Types ---

// JournalOperation names a kind of journaled vault operation. Constants
// below cover every operation the forward path writes.
type JournalOperation string

// JournalStateName names an observable in-flight state of a journaled
// operation. Constants below cover every mid-state plus the terminal
// StateComplete. Forward-path code must use these constants — not raw
// strings — so that recovery and forward stay synchronised through the
// type system.
type JournalStateName string

// --- Constants ---

const (
	OpLock   JournalOperation = "lock"
	OpUnlock JournalOperation = "unlock"
)

const (
	// Lock states (folder + file).
	StateEncrypting        JournalStateName = "encrypting"
	StateRemovingOriginals JournalStateName = "removing-originals"

	// Unlock states (folder + file).
	StateDecrypting        JournalStateName = "decrypting"
	StateRemovingEncrypted JournalStateName = "removing-encrypted"

	// StateComplete is written immediately before the journal is removed.
	// Has no recovery entry — observation only on a crash between write
	// and remove, where "do nothing, then clean up the journal" is the
	// right behaviour and is provided by the unconditional removeJournal
	// at the end of recovery.
	StateComplete JournalStateName = "complete"
)

// --- Package-level vars ---

// folderRecovery maps (operation, mid-state) → recovery action for
// folder vaults. The path passed in is the protected folder path,
// which is also where the journal lives.
//
// Missing entries are treated as no-op. The journal is always removed
// at the end of recovery regardless of whether an entry ran.
var folderRecovery = map[JournalOperation]map[JournalStateName]func(folderPath string) error{
	OpLock: {
		StateEncrypting: func(folderPath string) error {
			removeEncryptedData(folderPath)
			_ = os.Remove(manifestPath(folderPath))
			return nil
		},
		StateRemovingOriginals: noopRecovery,
	},
	OpUnlock: {
		StateDecrypting: func(folderPath string) error {
			removePartialDecrypts(folderPath)
			return nil
		},
		StateRemovingEncrypted: func(folderPath string) error {
			removeEncryptedData(folderPath)
			_ = os.Remove(manifestPath(folderPath))
			return nil
		},
	},
}

// fileRecovery maps (operation, mid-state) → recovery action for
// single-file vaults. The path passed in is the original file path
// (filePath); the journal lives in fileVaultDir(filePath).
//
// Different states need different paths: lock/encrypting and
// removing-encrypted operate on the vault dir; unlock/decrypting
// removes the partial plaintext at the original path. Each closure
// derives what it needs from filePath.
var fileRecovery = map[JournalOperation]map[JournalStateName]func(filePath string) error{
	OpLock: {
		StateEncrypting: func(filePath string) error {
			_ = os.RemoveAll(fileVaultDir(filePath))
			return nil
		},
		StateRemovingOriginals: noopRecovery,
	},
	OpUnlock: {
		StateDecrypting: func(filePath string) error {
			// Encrypted data intact in vault dir; remove the
			// partial plaintext so the vault stays in a clean
			// locked state.
			_ = os.Remove(filePath)
			return nil
		},
		StateRemovingEncrypted: func(filePath string) error {
			_ = os.RemoveAll(fileVaultDir(filePath))
			return nil
		},
	},
}

// --- Private package-level helpers ---

func noopRecovery(string) error { return nil }
