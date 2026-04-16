package main

import (
	"fmt"
	"sync"

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
	AdminGate           string `json:"admin_gate"`
}

type App struct {
	mu           sync.Mutex
	secureCfg    *monban.SecureConfig
	locked       bool
	masterSecret []byte // in-memory only, zeroed on lock
	encKey       []byte // derived file encryption key, zeroed on lock
	window       *application.WebviewWindow
	ipc          *ipcState
}

func NewApp() *App {
	return &App{locked: true}
}

func (a *App) SetWindow(w *application.WebviewWindow) {
	a.window = w
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

// DetectDevice checks if a FIDO2 device is connected.
func (a *App) DetectDevice() (bool, error) {
	return monban.DetectDevice()
}

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
