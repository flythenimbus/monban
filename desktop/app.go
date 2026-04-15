package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"monban/internal/monban"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type AppStatus struct {
	Locked     bool          `json:"locked"`
	Registered bool          `json:"registered"`
	Vaults     []VaultStatus `json:"vaults"`
}

type VaultStatus struct {
	Label       string `json:"label"`
	Path        string `json:"path"`
	Type        string `json:"type,omitempty"`
	Locked      bool   `json:"locked"`
	DecryptMode string `json:"decrypt_mode"`
}

type KeyInfo struct {
	Label        string `json:"label"`
	CredentialID string `json:"credential_id"`
}

type DiskSpaceInfo struct {
	FolderGB      float64 `json:"folder_gb"`
	FreeGB        float64 `json:"free_gb"`
	SafeToMigrate bool    `json:"safe_to_migrate"`
}

// CombinedSettings is the frontend-facing settings object.
// All fields are stored in the HMAC-signed secure config.
type CombinedSettings struct {
	OpenOnStartup       bool   `json:"open_on_startup"`
	ForceAuthentication bool   `json:"force_authentication"`
	SudoGate            string `json:"sudo_gate"`
}

type App struct {
	mu           sync.Mutex
	secureCfg    *monban.SecureConfig
	locked       bool
	masterSecret []byte // in-memory only, zeroed on lock
	encKey       []byte // derived file encryption key, zeroed on lock
	window       *application.WebviewWindow
}

func NewApp() *App {
	return &App{locked: true}
}

func (a *App) SetWindow(w *application.WebviewWindow) {
	a.window = w
}

// StartDeviceWatcher polls for security key presence and counter file integrity,
// locking vaults if either the key is removed or the counter file is deleted.
func (a *App) StartDeviceWatcher() {
	const missThreshold = 2 // require 2 consecutive misses to avoid USB glitches
	misses := 0

	go func() {
		for {
			time.Sleep(2 * time.Second)

			if a.IsLocked() {
				misses = 0
				continue
			}

			triggerLock := false
			reason := ""

			// Check security key presence
			connected, err := monban.DetectDevice()
			if err != nil || !connected {
				misses++
				if misses >= missThreshold {
					triggerLock = true
					reason = "security key removed"
				}
			} else {
				misses = 0
			}

			// Check counter file integrity
			if !triggerLock && !monban.CounterFileExists() {
				triggerLock = true
				reason = "counter file deleted"
			}

			if triggerLock {
				log.Printf("monban: %s, locking vaults...", reason)
				if err := a.Lock(); err != nil {
					log.Printf("monban: error locking: %v", err)
				}
				a.EnterFullscreen()
				if a.window != nil {
					a.window.EmitEvent("app:locked")
				}
				misses = 0
			}
		}
	}()
}

// ExitFullscreen switches the window to normal mode after unlock.
func (a *App) ExitFullscreen() {
	ExitKioskMode()
	if a.window != nil {
		a.window.UnFullscreen()
		a.window.SetSize(420, 300)
		a.window.Center()
		a.window.SetCloseButtonState(application.ButtonEnabled)
		a.window.SetMinimiseButtonState(application.ButtonEnabled)
		a.window.SetMaximiseButtonState(application.ButtonEnabled)
		a.window.SetAlwaysOnTop(false)
	}
}

// ResizeWindow resizes the window to fit content.
func (a *App) ResizeWindow(width, height int) {
	if a.window != nil {
		a.window.SetSize(width, height)
	}
}

// EnterFullscreen switches the window to fullscreen for the lock screen.
// If force authentication is enabled, activates kiosk mode.
func (a *App) EnterFullscreen() {
	if a.window == nil {
		return
	}
	settings := a.GetSettings()
	if settings.ForceAuthentication {
		a.window.SetCloseButtonState(application.ButtonHidden)
		a.window.SetMinimiseButtonState(application.ButtonHidden)
		a.window.SetMaximiseButtonState(application.ButtonHidden)
		a.window.SetAlwaysOnTop(true)
		a.window.Fullscreen()
		EnterKioskMode()
	}
}

func (a *App) IsLocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.locked
}

func (a *App) IsRegistered() bool {
	return monban.SecureConfigExists()
}

// GetSettings returns settings from the secure config.
func (a *App) GetSettings() CombinedSettings {
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return CombinedSettings{OpenOnStartup: true, ForceAuthentication: true}
	}

	return CombinedSettings{
		OpenOnStartup:       sc.OpenOnStartup,
		ForceAuthentication: sc.ForceAuthentication,
		SudoGate:            sc.SudoGate,
	}
}

// UpdateSettings saves all settings to the HMAC-signed secure config.
// All changes require a fresh FIDO2 assertion (PIN + touch).
func (a *App) UpdateSettings(settings CombinedSettings, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return fmt.Errorf("loading secure config: %w", err)
	}

	prevForceAuth := sc.ForceAuthentication

	// Fresh FIDO2 assertion — all settings are security-relevant
	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 authorization required: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	sc.OpenOnStartup = settings.OpenOnStartup
	sc.ForceAuthentication = settings.ForceAuthentication
	sc.SudoGate = settings.SudoGate

	if settings.OpenOnStartup {
		installLaunchAgent()
	} else {
		removeLaunchAgent()
	}

	hmacSalt, err := monban.DecodeB64(sc.HmacSalt)
	if err != nil {
		return fmt.Errorf("decoding hmac salt: %w", err)
	}

	if err := a.saveSignedSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("applying settings: %w", err)
	}

	if settings.ForceAuthentication && !prevForceAuth && !HasAccessibilityPermission() {
		PromptAccessibilityPermission()
	}

	return nil
}

// GetSudoGateCommand returns the terminal command the user should run to
// install or remove the sudo gate PAM config. On macOS Tahoe+, /etc/pam.d/
// is TCC-protected and can only be written from Terminal with sudo.
func (a *App) GetSudoGateCommand(mode string) (string, error) {
	helperSrc, err := monban.PamHelperPath()
	if err != nil {
		return "", err
	}

	if mode == "" || mode == "off" {
		return fmt.Sprintf("sudo '%s' --uninstall", helperSrc), nil
	}

	return fmt.Sprintf("sudo '%s' --install %s", helperSrc, mode), nil
}

// DetectDevice checks if a FIDO2 device is connected.
func (a *App) DetectDevice() (bool, error) {
	return monban.DetectDevice()
}

// Register creates a new FIDO2 credential and wraps the master secret with it.
// If this is the first credential, generates the master secret and hmac salt.
// If credentials already exist, wraps the existing master secret with the new key.
func (a *App) Register(pin string, label string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Register credential on security key
	cred, err := monban.Register(pin)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	var sc *monban.SecureConfig
	var hmacSalt []byte
	var masterSecret []byte
	isFirstReg := !monban.SecureConfigExists()

	if !isFirstReg {
		sc, hmacSalt, masterSecret, err = a.prepareAdditionalKey()
	} else {
		sc, hmacSalt, masterSecret, err = a.prepareFirstRegistration()
	}
	if err != nil {
		return err
	}

	// For first registration, zero the new master secret on any error path.
	// On success it gets assigned to a.masterSecret (cleared on Lock).
	registered := false
	if isFirstReg {
		defer func() {
			if !registered {
				monban.ZeroBytes(masterSecret)
			}
		}()
	}

	// Assert immediately to get hmac-secret for key wrapping
	assertion, err := monban.Assert(pin, [][]byte{cred.ID}, hmacSalt)
	if err != nil {
		return fmt.Errorf("assertion for key wrapping: %w", err)
	}

	if len(assertion.HMACSecret) == 0 {
		return fmt.Errorf("security key did not return hmac-secret")
	}

	// Verify the assertion signature
	cdh := sha256.Sum256(hmacSalt)
	if err := monban.VerifyAssertion(sc.RpID, cred.PubX, cred.PubY, cdh[:], assertion.AuthDataCBOR, assertion.Sig); err != nil {
		return fmt.Errorf("assertion verification failed: %w", err)
	}

	// Derive wrapping key and wrap the master secret
	wrappingKey, err := monban.DeriveWrappingKey(assertion.HMACSecret, hmacSalt)
	defer monban.ZeroBytes(assertion.HMACSecret, wrappingKey)
	if err != nil {
		return err
	}

	wrapped, err := monban.WrapKey(wrappingKey, masterSecret)
	if err != nil {
		return fmt.Errorf("wrapping master secret: %w", err)
	}

	// Add credential to secure config
	sc.Credentials = append(sc.Credentials, monban.CredentialEntry{
		Label:        label,
		CredentialID: monban.EncodeB64(cred.ID),
		PublicKeyX:   monban.EncodeB64(cred.PubX),
		PublicKeyY:   monban.EncodeB64(cred.PubY),
		WrappedKey:   monban.EncodeB64(wrapped),
	})

	// Sign and save secure config (root escalation)
	if err := a.saveSignedSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("saving secure config: %w", err)
	}

	// Derive encryption key and unlock
	encKey, err := monban.DeriveEncryptionKey(masterSecret, hmacSalt)
	if err != nil {
		return err
	}

	a.secureCfg = sc
	a.masterSecret = masterSecret
	a.encKey = encKey
	a.locked = false
	registered = true

	monban.LockConfigDir()

	return nil
}

// Unlock performs FIDO2 assertion, unwraps the master secret, and decrypts all vaults.
func (a *App) Unlock(pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return fmt.Errorf("loading secure config: %w", err)
	}

	if len(sc.Credentials) == 0 {
		return fmt.Errorf("no credentials registered")
	}

	hmacSalt, err := monban.DecodeB64(sc.HmacSalt)
	if err != nil {
		return fmt.Errorf("decoding hmac salt: %w", err)
	}

	// Collect all credential IDs
	credIDs := make([][]byte, len(sc.Credentials))
	for i, c := range sc.Credentials {
		id, err := monban.DecodeB64(c.CredentialID)
		if err != nil {
			return fmt.Errorf("decoding credential ID: %w", err)
		}
		credIDs[i] = id
	}

	// Assert with all credential IDs — device responds to the one it recognizes
	assertion, err := monban.Assert(pin, credIDs, hmacSalt)
	if err != nil {
		return fmt.Errorf("FIDO2 assertion failed: %w", err)
	}

	if len(assertion.HMACSecret) == 0 {
		return fmt.Errorf("security key did not return hmac-secret")
	}

	// Derive wrapping key from this assertion's hmac-secret
	wrappingKey, err := monban.DeriveWrappingKey(assertion.HMACSecret, hmacSalt)
	defer monban.ZeroBytes(assertion.HMACSecret, wrappingKey)
	if err != nil {
		return err
	}

	// Try unwrapping each credential's wrapped key — AES-GCM auth tag validates only for the correct one
	var masterSecret []byte
	var matchedCred *monban.CredentialEntry
	for i := range sc.Credentials {
		wrapped, err := monban.DecodeB64(sc.Credentials[i].WrappedKey)
		if err != nil {
			continue
		}
		secret, err := monban.UnwrapKey(wrappingKey, wrapped)
		if err != nil {
			continue // wrong key, try next
		}
		masterSecret = secret
		matchedCred = &sc.Credentials[i]
		break
	}

	if masterSecret == nil {
		return fmt.Errorf("could not unwrap master secret — no matching credential found")
	}

	// Verify assertion signature with the matched credential's public key
	pubX, err := monban.DecodeB64(matchedCred.PublicKeyX)
	if err != nil {
		return fmt.Errorf("decoding public key X: %w", err)
	}
	pubY, err := monban.DecodeB64(matchedCred.PublicKeyY)
	if err != nil {
		return fmt.Errorf("decoding public key Y: %w", err)
	}
	cdh := sha256.Sum256(hmacSalt)
	if err := monban.VerifyAssertion(sc.RpID, pubX, pubY, cdh[:], assertion.AuthDataCBOR, assertion.Sig); err != nil {
		return fmt.Errorf("assertion verification failed: %w", err)
	}

	// Verify secure config HMAC (tamper detection)
	if err := monban.VerifySecureConfig(sc, masterSecret, hmacSalt); err != nil {
		if err == monban.ErrConfigUnsigned {
			// First unlock after upgrade — sign and write counter
			log.Println("secure config unsigned, signing on first unlock")
			sc.ConfigCounter++
			if signErr := monban.SignSecureConfig(sc, masterSecret, hmacSalt); signErr == nil {
				_ = monban.SaveSecureConfig(sc)
				encKeyTmp, dErr := monban.DeriveEncryptionKey(masterSecret, hmacSalt)
				if dErr == nil {
					_ = monban.SaveCounter(encKeyTmp, sc.ConfigCounter)
					monban.ZeroBytes(encKeyTmp)
				}
			}
		} else {
			return fmt.Errorf("secure config integrity check failed — possible tampering detected")
		}
	}

	// Derive file encryption key
	encKey, err := monban.DeriveEncryptionKey(masterSecret, hmacSalt)
	if err != nil {
		return err
	}

	// Verify counter (rollback detection)
	storedCounter, counterErr := monban.LoadCounter(encKey)
	counterMissing := counterErr != nil && sc.ConfigCounter > 0
	if counterErr != nil && sc.ConfigCounter > 0 {
		log.Printf("monban: counter file missing or unreadable with non-zero config counter — possible deletion")
	} else if counterErr != nil {
		log.Printf("monban: could not load counter: %v (may be first run)", counterErr)
	}
	if counterMissing || sc.ConfigCounter < storedCounter {
		log.Printf("monban: config rollback detected (config=%d, counter=%d) — healing", sc.ConfigCounter, storedCounter)
		// Don't reject — this could be a legitimate backup restore.
		// The user already proved possession of the security key via FIDO2.
		// Heal the counter and re-sign.
		sc.ConfigCounter = storedCounter
		if signErr := monban.SignSecureConfig(sc, masterSecret, hmacSalt); signErr == nil {
			_ = monban.SaveSecureConfig(sc)
			_ = monban.SaveCounter(encKey, sc.ConfigCounter)
		}
		if a.window != nil {
			a.window.EmitEvent("app:config-rollback-detected")
		}
	}

	// Unlock all eager vaults
	for _, v := range sc.Vaults {
		if sc.VaultDecryptMode(v.Path) != monban.DecryptEager {
			continue
		}
		if err := monban.UnlockVaultEntry(encKey, v); err != nil {
			return err
		}
	}

	a.secureCfg = sc
	a.masterSecret = masterSecret
	a.encKey = encKey
	a.locked = false

	monban.LockConfigDir()

	return nil
}

// Lock encrypts all vaults and clears secrets from memory.
func (a *App) Lock() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.secureCfg == nil {
		return fmt.Errorf("config not found")
	}

	// Restore directory write permission for vault locking
	monban.UnlockConfigDir()

	hmacSalt, err := monban.DecodeB64(a.secureCfg.HmacSalt)
	if err != nil {
		return fmt.Errorf("decoding hmac salt: %w", err)
	}

	var lockErr error
	for _, v := range a.secureCfg.Vaults {
		mode := a.secureCfg.VaultDecryptMode(v.Path)
		if mode == monban.DecryptLazyStrict {
			lazyKey, err := monban.DeriveLazyStrictKey(a.masterSecret, hmacSalt, v.Path)
			if err != nil {
				lockErr = fmt.Errorf("deriving lazy strict key: %w", err)
				break
			}
			if err := monban.LockVaultEntry(lazyKey, v); err != nil {
				monban.ZeroBytes(lazyKey)
				lockErr = err
				break
			}
			monban.ZeroBytes(lazyKey)
		} else {
			if err := monban.LockVaultEntry(a.encKey, v); err != nil {
				lockErr = err
				break
			}
		}
	}

	// Always zero secrets and re-lock directory, even on error
	monban.ZeroBytes(a.masterSecret)
	monban.ZeroBytes(a.encKey)
	a.masterSecret = nil
	a.encKey = nil
	a.locked = true
	monban.LockConfigDir()

	return lockErr
}

// GetStatus returns the current app state.
func (a *App) GetStatus() AppStatus {
	a.mu.Lock()
	defer a.mu.Unlock()

	status := AppStatus{
		Locked:     a.locked,
		Registered: monban.SecureConfigExists(),
	}

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return status
	}

	for _, v := range sc.Vaults {
		locked := false
		if v.IsFile() {
			locked = monban.IsFileLocked(v.Path)
		} else {
			locked = monban.IsLocked(v.Path)
		}
		decryptMode := string(sc.VaultDecryptMode(v.Path))
		status.Vaults = append(status.Vaults, VaultStatus{
			Label:       v.Label,
			Path:        v.Path,
			Type:        v.Type,
			Locked:      locked,
			DecryptMode: decryptMode,
		})
	}

	return status
}

// ListKeys returns information about registered security keys.
func (a *App) ListKeys() ([]KeyInfo, error) {
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return nil, err
	}

	keys := make([]KeyInfo, len(sc.Credentials))
	for i, c := range sc.Credentials {
		keys[i] = KeyInfo{
			Label:        c.Label,
			CredentialID: c.CredentialID,
		}
	}
	return keys, nil
}

// RemoveKey removes a registered credential. Cannot remove the last key.
// Requires FIDO2 re-auth.
func (a *App) RemoveKey(credentialID string, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return fmt.Errorf("must be unlocked to remove a key")
	}

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return err
	}

	if len(sc.Credentials) <= 1 {
		return fmt.Errorf("cannot remove the last registered key")
	}

	idx := -1
	for i, c := range sc.Credentials {
		if c.CredentialID == credentialID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("credential not found")
	}

	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 authorization required: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	sc.Credentials = append(sc.Credentials[:idx], sc.Credentials[idx+1:]...)

	hmacSalt, err := monban.DecodeB64(sc.HmacSalt)
	if err != nil {
		return fmt.Errorf("decoding hmac salt: %w", err)
	}

	if err := a.saveSignedSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("saving secure config: %w", err)
	}

	a.secureCfg = sc
	return nil
}

// RevealSecureConfig opens the system file manager to the secure config directory.
func (a *App) RevealSecureConfig() error {
	dir := monban.SecureConfigDir()
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", dir).Start()
	case "linux":
		return exec.Command("xdg-open", dir).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}

// CheckDiskSpace returns disk space info for a folder.
func (a *App) CheckDiskSpace(path string) DiskSpaceInfo {
	folderBytes, err := monban.FolderSize(path)
	if err != nil {
		return DiskSpaceInfo{}
	}

	freeBytes, err := monban.FreeSpace(path)
	if err != nil {
		return DiskSpaceInfo{}
	}

	folderGB := float64(folderBytes) / (1024 * 1024 * 1024)
	freeGB := float64(freeBytes) / (1024 * 1024 * 1024)

	return DiskSpaceInfo{
		FolderGB:      folderGB,
		FreeGB:        freeGB,
		SafeToMigrate: freeBytes >= 2*folderBytes,
	}
}

// AddFolder adds a folder to the protected list. Files are encrypted in place on lock.
func (a *App) AddPath(path string, pin string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("path not found: %w", err)
	}
	if info.IsDir() {
		return a.addFolder(absPath, pin)
	}
	return a.addFile(absPath, pin)
}

// RemoveFolder removes a folder from protection. Ensures files are decrypted first.
// Requires FIDO2 re-auth.
func (a *App) RemoveFolder(folderPath string, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked || a.encKey == nil {
		return fmt.Errorf("must be unlocked to remove folders")
	}

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return err
	}

	idx := monban.FindVaultIndex(sc.Vaults, folderPath)
	if idx == -1 {
		return fmt.Errorf("folder not found: %s", folderPath)
	}

	// Ensure files are decrypted
	if err := monban.UnlockVaultEntry(a.encKey, sc.Vaults[idx]); err != nil {
		return err
	}

	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 authorization required: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	sc.Vaults = append(sc.Vaults[:idx], sc.Vaults[idx+1:]...)

	hmacSalt, err := monban.DecodeB64(sc.HmacSalt)
	if err != nil {
		return fmt.Errorf("decoding hmac salt: %w", err)
	}
	if err := a.saveSignedSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	a.secureCfg = sc
	return nil
}

func (a *App) DecryptLazyVault(path string, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.secureCfg == nil {
		return fmt.Errorf("no config found")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	idx := monban.FindVaultIndex(a.secureCfg.Vaults, absPath)
	if idx == -1 {
		return fmt.Errorf("not found: %s", absPath)
	}

	v := a.secureCfg.Vaults[idx]
	decMode := a.secureCfg.VaultDecryptMode(absPath)

	if decMode == monban.DecryptEager || decMode == monban.DecryptLazy {
		if err := monban.UnlockVaultEntry(a.encKey, v); err != nil {
			return err
		}
		return nil
	}

	// lazy_strict: re-authenticate with FIDO2 to derive per-vault key
	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 re-auth failed: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	hmacSalt, err := monban.DecodeB64(a.secureCfg.HmacSalt)
	if err != nil {
		return fmt.Errorf("decoding hmac salt: %w", err)
	}

	lazyStrictKey, err := monban.DeriveLazyStrictKey(masterSecret, hmacSalt, absPath)
	if err != nil {
		return fmt.Errorf("deriving lazy strict key: %w", err)
	}
	defer monban.ZeroBytes(lazyStrictKey)

	if err := monban.UnlockVaultEntry(lazyStrictKey, v); err != nil {
		return err
	}

	return nil
}

// LockVault re-encrypts a single vault on demand.
func (a *App) LockVault(path string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return fmt.Errorf("app is locked")
	}

	if a.secureCfg == nil {
		return fmt.Errorf("no config found")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	idx := monban.FindVaultIndex(a.secureCfg.Vaults, absPath)
	if idx == -1 {
		return fmt.Errorf("not found: %s", absPath)
	}

	v := a.secureCfg.Vaults[idx]
	mode := a.secureCfg.VaultDecryptMode(absPath)

	if mode == monban.DecryptLazyStrict {
		hmacSalt, err := monban.DecodeB64(a.secureCfg.HmacSalt)
		if err != nil {
			return fmt.Errorf("decoding hmac salt: %w", err)
		}
		lazyKey, err := monban.DeriveLazyStrictKey(a.masterSecret, hmacSalt, absPath)
		if err != nil {
			return fmt.Errorf("deriving lazy strict key: %w", err)
		}
		if err := monban.LockVaultEntry(lazyKey, v); err != nil {
			monban.ZeroBytes(lazyKey)
			return err
		}
		monban.ZeroBytes(lazyKey)
	} else {
		if err := monban.LockVaultEntry(a.encKey, v); err != nil {
			return err
		}
	}

	return nil
}

// UpdateVaultMode changes the decrypt mode for a vault. Requires FIDO2 re-auth.
func (a *App) UpdateVaultMode(path string, mode string, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return fmt.Errorf("must be unlocked")
	}

	if a.secureCfg == nil {
		return fmt.Errorf("no config found")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	idx := monban.FindVaultIndex(a.secureCfg.Vaults, absPath)
	if idx == -1 {
		return fmt.Errorf("not found: %s", absPath)
	}

	v := a.secureCfg.Vaults[idx]
	newMode := monban.DecryptMode(mode)
	oldMode := a.secureCfg.VaultDecryptMode(absPath)

	if oldMode == newMode {
		return nil
	}

	// FIDO2 re-auth for all mode changes
	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 authorization required: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	hmacSalt, err := monban.DecodeB64(a.secureCfg.HmacSalt)
	if err != nil {
		return fmt.Errorf("decoding hmac salt: %w", err)
	}

	switch {
	case oldMode != monban.DecryptLazyStrict && newMode != monban.DecryptLazyStrict:
		// eager <-> lazy: no re-encryption needed, just update flag

	case oldMode != monban.DecryptLazyStrict && newMode == monban.DecryptLazyStrict:
		if err := monban.UnlockVaultEntry(a.encKey, v); err != nil {
			return fmt.Errorf("decrypting vault for mode change: %w", err)
		}
		lazyStrictKey, err := monban.DeriveLazyStrictKey(masterSecret, hmacSalt, absPath)
		if err != nil {
			return fmt.Errorf("deriving lazy strict key: %w", err)
		}
		if err := monban.LockVaultEntry(lazyStrictKey, v); err != nil {
			monban.ZeroBytes(lazyStrictKey)
			return fmt.Errorf("re-encrypting vault with lazy strict key: %w", err)
		}
		monban.ZeroBytes(lazyStrictKey)

	case oldMode == monban.DecryptLazyStrict && newMode != monban.DecryptLazyStrict:
		lazyStrictKey, err := monban.DeriveLazyStrictKey(masterSecret, hmacSalt, absPath)
		if err != nil {
			return fmt.Errorf("deriving lazy strict key: %w", err)
		}
		if err := monban.UnlockVaultEntry(lazyStrictKey, v); err != nil {
			monban.ZeroBytes(lazyStrictKey)
			return fmt.Errorf("decrypting vault from lazy strict: %w", err)
		}
		monban.ZeroBytes(lazyStrictKey)

		if newMode == monban.DecryptLazy {
			if err := monban.LockVaultEntry(a.encKey, v); err != nil {
				return fmt.Errorf("re-encrypting vault with enc key: %w", err)
			}
		}
	}

	// Update the mode in secure config
	if a.secureCfg.VaultDecryptModes == nil {
		a.secureCfg.VaultDecryptModes = make(map[string]monban.DecryptMode)
	}
	if newMode == monban.DecryptEager {
		delete(a.secureCfg.VaultDecryptModes, absPath)
	} else {
		a.secureCfg.VaultDecryptModes[absPath] = newMode
	}

	if err := a.saveSignedSecureConfig(a.secureCfg, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("saving secure config: %w", err)
	}

	return nil
}

