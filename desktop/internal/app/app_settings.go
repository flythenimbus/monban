package app

import (
	"fmt"

	"monban/internal/monban"
)

// GetSettings returns settings from the secure config.
func (a *App) GetSettings() CombinedSettings {
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return CombinedSettings{OpenOnStartup: true, ForceAuthentication: true}
	}

	return CombinedSettings{
		OpenOnStartup:       sc.OpenOnStartup,
		ForceAuthentication: sc.ForceAuthentication,
		AdminGate:           sc.AdminGate,
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
	sc.AdminGate = settings.AdminGate

	if settings.OpenOnStartup {
		InstallLaunchAgent()
	} else {
		RemoveLaunchAgent()
	}

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return err
	}

	if err := a.saveSignedSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("applying settings: %w", err)
	}

	if settings.ForceAuthentication && !prevForceAuth && !HasAccessibilityPermission() {
		PromptAccessibilityPermission()
	}

	return nil
}

// GetAdminGateCommand returns the terminal command the user should run to
// install or remove the admin gate. Installs sudo PAM gate on all platforms
// and the authorization plugin on macOS.
func (a *App) GetAdminGateCommand(mode string) (string, error) {
	helperSrc, err := monban.PamHelperPath()
	if err != nil {
		return "", err
	}

	if mode == "" || mode == "off" {
		return fmt.Sprintf("sudo '%s' --uninstall", helperSrc), nil
	}

	return fmt.Sprintf("sudo '%s' --install %s", helperSrc, mode), nil
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

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return err
	}

	if err := a.saveSignedSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("saving secure config: %w", err)
	}

	a.secureCfg = sc
	return nil
}
