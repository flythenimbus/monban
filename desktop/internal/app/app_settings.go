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
	}
}

// UpdateSettings saves all settings to the HMAC-signed secure config.
// All changes require a fresh FIDO2 assertion (PIN + touch).
//
// Note: admin_gate (sudo / admin-dialog gating) is no longer a runtime setting
// on macOS — it is configured once at pkg install time. See plans/macos_install.md
// Phase 2.5 for the rationale.
func (a *App) UpdateSettings(settings CombinedSettings, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var prevForceAuth bool
	err := a.withAuthConfigMutation(pin,
		func(sc *monban.SecureConfig) error {
			prevForceAuth = sc.ForceAuthentication
			return nil
		},
		func(sc *monban.SecureConfig, _ *monban.MasterSecret, _ []byte) error {
			sc.OpenOnStartup = settings.OpenOnStartup
			sc.ForceAuthentication = settings.ForceAuthentication
			if settings.OpenOnStartup {
				InstallLaunchAgent()
			} else {
				RemoveLaunchAgent()
			}
			return nil
		},
	)
	if err != nil {
		return err
	}

	if settings.ForceAuthentication && !prevForceAuth && !hasAccessibilityPermission() {
		promptAccessibilityPermission()
	}

	a.pluginHost.Fire("on:settings_changed", map[string]any{
		"pluginName": "core",
	})

	return nil
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

	var removed monban.CredentialEntry
	err := a.withAuthConfigMutation(pin,
		func(sc *monban.SecureConfig) error {
			if len(sc.Credentials) <= 1 {
				return fmt.Errorf("cannot remove the last registered key")
			}
			for _, c := range sc.Credentials {
				if c.CredentialID == credentialID {
					removed = c
					return nil
				}
			}
			return fmt.Errorf("credential not found")
		},
		func(sc *monban.SecureConfig, _ *monban.MasterSecret, _ []byte) error {
			for i, c := range sc.Credentials {
				if c.CredentialID == credentialID {
					sc.Credentials = append(sc.Credentials[:i], sc.Credentials[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("credential not found")
		},
	)
	if err != nil {
		return err
	}

	a.pluginHost.Fire("on:key_removed", map[string]any{
		"credentialID": removed.CredentialID,
		"label":        removed.Label,
	})
	return nil
}
