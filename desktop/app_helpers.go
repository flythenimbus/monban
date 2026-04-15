package main

import (
	"fmt"
	"os"
	"path/filepath"

	"monban/internal/monban"
)

// saveSignedSecureConfig increments the counter, signs the config, saves it,
// and writes the encrypted counter file. Caller must hold a.mu and ensure
// masterSecret, hmacSalt, and encKey are valid.
func (a *App) saveSignedSecureConfig(sc *monban.SecureConfig, masterSecret, hmacSalt []byte) error {
	sc.ConfigCounter++

	if err := monban.SignSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("signing secure config: %w", err)
	}
	if err := monban.SaveSecureConfig(sc); err != nil {
		return err
	}

	// Write encrypted counter — requires encKey (derived from master secret)
	encKey := a.encKey
	if encKey == nil {
		// During registration, encKey isn't set yet — derive it
		var err error
		encKey, err = monban.DeriveEncryptionKey(masterSecret, hmacSalt)
		if err != nil {
			return fmt.Errorf("deriving enc key for counter: %w", err)
		}
		defer monban.ZeroBytes(encKey)
	}

	if err := monban.SaveCounter(encKey, sc.ConfigCounter); err != nil {
		return fmt.Errorf("saving counter: %w", err)
	}

	return nil
}

// prepareAdditionalKey loads the existing secure config and master secret
// for wrapping with a new key. The app must be unlocked.
func (a *App) prepareAdditionalKey() (*monban.SecureConfig, []byte, []byte, error) {
	if a.locked || a.masterSecret == nil {
		return nil, nil, nil, fmt.Errorf("must be unlocked to add a new key")
	}
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading secure config: %w", err)
	}
	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return nil, nil, nil, err
	}
	return sc, hmacSalt, a.masterSecret, nil
}

// prepareFirstRegistration generates a fresh master secret, hmac salt,
// and secure config for initial setup.
func (a *App) prepareFirstRegistration() (*monban.SecureConfig, []byte, []byte, error) {
	hmacSalt, err := monban.GenerateHmacSalt()
	if err != nil {
		return nil, nil, nil, err
	}
	masterSecret, err := monban.GenerateMasterSecret()
	if err != nil {
		return nil, nil, nil, err
	}
	sc := &monban.SecureConfig{
		RpID:                "monban.local",
		HmacSalt:            monban.EncodeB64(hmacSalt),
		Credentials:         []monban.CredentialEntry{},
		ForceAuthentication: true,
		Vaults:              []monban.VaultEntry{},
		OpenOnStartup:       true,
	}

	return sc, hmacSalt, masterSecret, nil
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

// fidoReauth performs FIDO2 re-authentication and returns a fresh master secret.
// The caller is responsible for zeroing the returned secret.
// Must be called with a.mu held.
func (a *App) fidoReauth(pin string) ([]byte, error) {
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return nil, fmt.Errorf("loading secure config: %w", err)
	}

	if len(sc.Credentials) == 0 {
		return nil, fmt.Errorf("no credentials registered")
	}

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return nil, err
	}

	credIDs, err := sc.CollectCredentialIDs()
	if err != nil {
		return nil, err
	}

	assertion, err := monban.Assert(pin, credIDs, hmacSalt)
	if err != nil {
		return nil, fmt.Errorf("FIDO2 assertion failed: %w", err)
	}

	if len(assertion.HMACSecret) == 0 {
		return nil, fmt.Errorf("security key did not return hmac-secret")
	}

	wrappingKey, err := monban.DeriveWrappingKey(assertion.HMACSecret, hmacSalt)
	defer monban.ZeroBytes(assertion.HMACSecret, wrappingKey)
	if err != nil {
		return nil, err
	}

	masterSecret, matchedCred, err := monban.UnwrapMasterSecret(sc, wrappingKey)
	if err != nil {
		return nil, err
	}

	if err := monban.VerifyAssertionWithSalt(sc.RpID, matchedCred, hmacSalt, assertion.AuthDataCBOR, assertion.Sig); err != nil {
		monban.ZeroBytes(masterSecret)
		return nil, fmt.Errorf("assertion verification failed: %w", err)
	}

	return masterSecret, nil
}
