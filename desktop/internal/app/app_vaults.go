package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"monban/internal/monban"
)

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

// AddPath adds a folder or file to the protected list.
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

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return err
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

	hmacSalt, err := a.secureCfg.DecodeHmacSalt()
	if err != nil {
		return err
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
		hmacSalt, err := a.secureCfg.DecodeHmacSalt()
		if err != nil {
			return err
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

	hmacSalt, err := a.secureCfg.DecodeHmacSalt()
	if err != nil {
		return err
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

// addFolder is the internal implementation. Caller must NOT hold a.mu.
func (a *App) addFolder(absPath string, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked || a.encKey == nil {
		return fmt.Errorf("must be unlocked to add folders")
	}

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return err
	}

	if monban.FindVaultIndex(sc.Vaults, absPath) != -1 {
		return fmt.Errorf("already protected: %s", absPath)
	}
	if err := monban.CheckVaultOverlap(sc.Vaults, absPath); err != nil {
		return err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("folder not found: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory: %s", absPath)
	}

	folderBytes, err := monban.FolderSize(absPath)
	if err != nil {
		return fmt.Errorf("measuring folder: %w", err)
	}
	if err := monban.ValidateDiskSpace(absPath, folderBytes); err != nil {
		return err
	}

	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 authorization required: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	label := filepath.Base(absPath)
	sc.Vaults = append(sc.Vaults, monban.VaultEntry{
		Label: label,
		Path:  absPath,
	})

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return err
	}
	if err := a.saveSignedSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	a.secureCfg = sc
	return nil
}

// addFile is the internal implementation. Caller must NOT hold a.mu.
func (a *App) addFile(absPath string, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked || a.encKey == nil {
		return fmt.Errorf("must be unlocked to add files")
	}

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return err
	}

	if monban.FindVaultIndex(sc.Vaults, absPath) != -1 {
		return fmt.Errorf("already protected: %s", absPath)
	}
	if err := monban.CheckVaultOverlap(sc.Vaults, absPath); err != nil {
		return err
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("file not found: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory: %s", absPath)
	}

	if err := monban.ValidateDiskSpace(absPath, info.Size()); err != nil {
		return err
	}

	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 authorization required: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	label := filepath.Base(absPath)
	sc.Vaults = append(sc.Vaults, monban.VaultEntry{
		Label: label,
		Path:  absPath,
		Type:  "file",
	})

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return err
	}
	if err := a.saveSignedSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	a.secureCfg = sc
	return nil
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
