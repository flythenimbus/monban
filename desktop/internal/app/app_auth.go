package app

import (
	"crypto/sha256"
	"fmt"
	"log"

	"monban/internal/monban"
)

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

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return err
	}

	// Collect all credential IDs
	credIDs, err := sc.CollectCredentialIDs()
	if err != nil {
		return err
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
	masterSecret, matchedCred, err := monban.UnwrapMasterSecret(sc, wrappingKey)
	if err != nil {
		return err
	}

	// Verify assertion signature with the matched credential's public key
	if err := monban.VerifyAssertionWithSalt(sc.RpID, matchedCred, hmacSalt, assertion.AuthDataCBOR, assertion.Sig); err != nil {
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

// Lock encrypts all vaults and clears secrets from memory.
func (a *App) Lock() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.secureCfg == nil {
		return fmt.Errorf("config not found")
	}

	// Restore directory write permission for vault locking
	monban.UnlockConfigDir()

	hmacSalt, err := a.secureCfg.DecodeHmacSalt()
	if err != nil {
		return err
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
