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
		decryptMode := string(sc.VaultDecryptMode(v.Path))
		status.Vaults = append(status.Vaults, VaultStatus{
			Label:       v.Label,
			Path:        v.Path,
			Type:        v.Type,
			Locked:      monban.VaultFor(v).IsLocked(),
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

	var removed monban.VaultEntry
	err := a.withAuthConfigMutation(pin,
		func(sc *monban.SecureConfig) error {
			idx := monban.FindVaultIndex(sc.Vaults, folderPath)
			if idx == -1 {
				return fmt.Errorf("folder not found: %s", folderPath)
			}
			removed = sc.Vaults[idx]
			// Decrypt before re-auth — fail fast on disk errors so we
			// don't waste a touch.
			return monban.VaultFor(removed).Unlock(a.encKey, nil)
		},
		func(sc *monban.SecureConfig, _ *monban.MasterSecret, _ []byte) error {
			idx := monban.FindVaultIndex(sc.Vaults, folderPath)
			if idx == -1 {
				return fmt.Errorf("folder not found: %s", folderPath)
			}
			sc.Vaults = append(sc.Vaults[:idx], sc.Vaults[idx+1:]...)
			return nil
		},
	)
	if err != nil {
		return err
	}

	a.pluginHost.Fire("on:vault_removed", map[string]any{
		"vaultPath": removed.Path,
		"type":      removed.Type,
	})
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
	vault := monban.VaultFor(v)
	decMode := a.secureCfg.VaultDecryptMode(absPath)

	if decMode == monban.DecryptEager || decMode == monban.DecryptLazy {
		progress := a.maybeProgressForUnlock(a.encKey, v)
		defer progress.Done()
		return vault.Unlock(a.encKey, progress.Func())
	}

	// lazy_strict: re-authenticate with FIDO2 to derive per-vault key
	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 re-auth failed: %w", err)
	}
	defer masterSecret.Zero()

	hmacSalt, err := a.secureCfg.DecodeHmacSalt()
	if err != nil {
		return err
	}

	lazyStrictKey, err := masterSecret.LazyStrictKey(hmacSalt, absPath)
	if err != nil {
		return fmt.Errorf("deriving lazy strict key: %w", err)
	}
	defer monban.ZeroBytes(lazyStrictKey)

	progress := a.maybeProgressForUnlock(lazyStrictKey, v)
	defer progress.Done()
	return vault.Unlock(lazyStrictKey, progress.Func())
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
	vault := monban.VaultFor(v)
	mode := a.secureCfg.VaultDecryptMode(absPath)

	progress := a.maybeProgressForLock(v)
	defer progress.Done()

	if mode == monban.DecryptLazyStrict {
		hmacSalt, err := a.secureCfg.DecodeHmacSalt()
		if err != nil {
			return err
		}
		lazyKey, err := a.masterSecret.LazyStrictKey(hmacSalt, absPath)
		if err != nil {
			return fmt.Errorf("deriving lazy strict key: %w", err)
		}
		if err := vault.Lock(lazyKey, progress.Func()); err != nil {
			monban.ZeroBytes(lazyKey)
			return err
		}
		monban.ZeroBytes(lazyKey)
	} else {
		if err := vault.Lock(a.encKey, progress.Func()); err != nil {
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

	vault := monban.VaultFor(v)
	return a.withAuthConfigMutation(pin, nil,
		func(sc *monban.SecureConfig, masterSecret *monban.MasterSecret, hmacSalt []byte) error {
			switch {
			case oldMode != monban.DecryptLazyStrict && newMode != monban.DecryptLazyStrict:
				// eager <-> lazy: no re-encryption needed, just update flag

			case oldMode != monban.DecryptLazyStrict && newMode == monban.DecryptLazyStrict:
				if err := vault.Unlock(a.encKey, nil); err != nil {
					return fmt.Errorf("decrypting vault for mode change: %w", err)
				}
				lazyStrictKey, err := masterSecret.LazyStrictKey(hmacSalt, absPath)
				if err != nil {
					return fmt.Errorf("deriving lazy strict key: %w", err)
				}
				if err := vault.Lock(lazyStrictKey, nil); err != nil {
					monban.ZeroBytes(lazyStrictKey)
					return fmt.Errorf("re-encrypting vault with lazy strict key: %w", err)
				}
				monban.ZeroBytes(lazyStrictKey)

			case oldMode == monban.DecryptLazyStrict && newMode != monban.DecryptLazyStrict:
				lazyStrictKey, err := masterSecret.LazyStrictKey(hmacSalt, absPath)
				if err != nil {
					return fmt.Errorf("deriving lazy strict key: %w", err)
				}
				if err := vault.Unlock(lazyStrictKey, nil); err != nil {
					monban.ZeroBytes(lazyStrictKey)
					return fmt.Errorf("decrypting vault from lazy strict: %w", err)
				}
				monban.ZeroBytes(lazyStrictKey)

				if newMode == monban.DecryptLazy {
					if err := vault.Lock(a.encKey, nil); err != nil {
						return fmt.Errorf("re-encrypting vault with enc key: %w", err)
					}
				}
			}

			if sc.VaultDecryptModes == nil {
				sc.VaultDecryptModes = make(map[string]monban.DecryptMode)
			}
			if newMode == monban.DecryptEager {
				delete(sc.VaultDecryptModes, absPath)
			} else {
				sc.VaultDecryptModes[absPath] = newMode
			}
			return nil
		},
	)
}

// addFolder is the internal implementation. Caller must NOT hold a.mu.
func (a *App) addFolder(absPath string, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked || a.encKey == nil {
		return fmt.Errorf("must be unlocked to add folders")
	}

	err := a.withAuthConfigMutation(pin,
		func(sc *monban.SecureConfig) error {
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
			return monban.ValidateDiskSpace(absPath, folderBytes)
		},
		func(sc *monban.SecureConfig, _ *monban.MasterSecret, _ []byte) error {
			sc.Vaults = append(sc.Vaults, monban.VaultEntry{
				Label: filepath.Base(absPath),
				Path:  absPath,
			})
			return nil
		},
	)
	if err != nil {
		return err
	}

	a.pluginHost.Fire("on:vault_added", map[string]any{
		"vaultPath": absPath,
		"type":      "",
	})
	return nil
}

// addFile is the internal implementation. Caller must NOT hold a.mu.
func (a *App) addFile(absPath string, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked || a.encKey == nil {
		return fmt.Errorf("must be unlocked to add files")
	}

	err := a.withAuthConfigMutation(pin,
		func(sc *monban.SecureConfig) error {
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
			return monban.ValidateDiskSpace(absPath, info.Size())
		},
		func(sc *monban.SecureConfig, _ *monban.MasterSecret, _ []byte) error {
			sc.Vaults = append(sc.Vaults, monban.VaultEntry{
				Label: filepath.Base(absPath),
				Path:  absPath,
				Type:  "file",
			})
			return nil
		},
	)
	if err != nil {
		return err
	}

	a.pluginHost.Fire("on:vault_added", map[string]any{
		"vaultPath": absPath,
		"type":      "file",
	})
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
