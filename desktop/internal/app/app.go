package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"monban/internal/monban"
	"monban/internal/plugin"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// removeAll is a thin wrapper so we can swap it in tests without touching
// the filesystem under HOME.
var removeAll = os.RemoveAll

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
	OpenOnStartup       bool `json:"open_on_startup"`
	ForceAuthentication bool `json:"force_authentication"`
}

type App struct {
	mu           sync.Mutex
	secureCfg    *monban.SecureConfig
	locked       bool
	masterSecret []byte // in-memory only, zeroed on lock
	encKey       []byte // derived file encryption key, zeroed on lock
	window       *application.WebviewWindow
	pluginHost   *plugin.Host
}

func NewApp() *App {
	a := &App{locked: true}
	a.pluginHost = plugin.NewHost(plugin.HostConfig{
		PluginsDir:         filepath.Join(monban.ConfigDir(), "plugins"),
		HostVersion:        Version,
		LoadPluginSettings: loadPluginSettingsFromConfig,
		OnRequestPinTouch: func(ctx context.Context, req plugin.PinTouchRequest) (*plugin.PinTouchResult, error) {
			return a.handlePluginPinTouch(ctx, req)
		},
	})
	return a
}

// handlePluginPinTouch is invoked when a plugin's helper asks the host
// to prompt the user for PIN + touch — typically the admin-gate
// SecurityAgent flow. P3a only scaffolds the RPC pipe; the UI wiring
// comes in P3b once the admin-gate plugin actually needs it.
func (a *App) handlePluginPinTouch(_ context.Context, _ plugin.PinTouchRequest) (*plugin.PinTouchResult, error) {
	return nil, fmt.Errorf("request_pin_touch not wired to UI yet")
}

// loadPluginSettingsFromConfig reads the persisted settings blob for name
// from SecureConfig. Returns nil when the config or entry is missing;
// plugins should use their manifest defaults in that case.
func loadPluginSettingsFromConfig(name string) json.RawMessage {
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return nil
	}
	return sc.PluginSettings[name]
}

// StartPluginHost loads every installed plugin from the plugins directory,
// verifies signatures, spawns subprocesses, and performs the hello
// handshake. Call early in main() so plugins are ready before the first
// lifecycle event fires.
func (a *App) StartPluginHost(ctx context.Context) {
	if err := a.pluginHost.Start(ctx); err != nil {
		log.Printf("monban: plugin host start: %v", err)
	}
}

// FirePluginEvent dispatches a lifecycle notify to subscribed plugins.
// P1 only emits on:app_started and on:app_shutdown.
func (a *App) FirePluginEvent(event string, payload any) {
	a.pluginHost.Fire(event, payload)
}

// ShutdownPluginHost notifies every loaded plugin that the app is exiting,
// then terminates each subprocess with a grace period.
func (a *App) ShutdownPluginHost() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.pluginHost.Fire("on:app_shutdown", nil)
	a.pluginHost.Shutdown(ctx)
}

// ListPlugins returns the current set of loaded plugins for the admin UI.
func (a *App) ListPlugins() []plugin.PluginStatus {
	return a.pluginHost.List()
}

// AvailablePlugin is a catalog entry filtered for the running platform,
// augmented with a flag telling the UI whether it's already installed.
type AvailablePlugin struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
}

// ListAvailablePlugins returns every plugin in the embedded catalog that
// can run on this platform, with installed-status resolved.
func (a *App) ListAvailablePlugins() []AvailablePlugin {
	cat, err := plugin.LoadCatalog()
	if err != nil {
		return nil
	}
	installed := map[string]bool{}
	for _, p := range a.pluginHost.List() {
		installed[p.Name] = true
	}
	platform := plugin.CurrentPlatform()
	out := make([]AvailablePlugin, 0, len(cat.Plugins))
	for _, e := range cat.Plugins {
		if !e.SupportsPlatform(platform) {
			continue
		}
		out = append(out, AvailablePlugin{
			Name:        e.Name,
			DisplayName: e.DisplayTitle(),
			Version:     e.Version,
			Description: e.Description,
			Installed:   installed[e.Name],
		})
	}
	return out
}

// InstallPlugin downloads the named plugin from the embedded catalog,
// verifies its signatures, extracts the tarball into the plugins dir,
// and loads it. Requires FIDO2 re-auth — installing a plugin adds
// HMAC-covered state to the secure config.
func (a *App) InstallPlugin(name, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return fmt.Errorf("must be unlocked to install plugins")
	}

	cat, err := plugin.LoadCatalog()
	if err != nil {
		return fmt.Errorf("catalog: %w", err)
	}
	var entry *plugin.CatalogEntry
	for i := range cat.Plugins {
		if cat.Plugins[i].Name == name {
			entry = &cat.Plugins[i]
			break
		}
	}
	if entry == nil {
		return fmt.Errorf("plugin %q not in catalog", name)
	}

	// FIDO reauth before any disk writes.
	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 authorization required: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	pluginsDir := filepath.Join(monban.ConfigDir(), "plugins")
	installer := plugin.NewInstaller(pluginsDir)

	monban.UnlockConfigDir()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dirName, installErr := installer.Install(ctx, entry)
	monban.LockConfigDir()
	if installErr != nil {
		return fmt.Errorf("install: %w", installErr)
	}

	// Load the fresh plugin into the running host.
	loadCtx, loadCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer loadCancel()
	if err := a.pluginHost.LoadOne(loadCtx, dirName); err != nil {
		return fmt.Errorf("load after install: %w", err)
	}

	// New plugin gets on:app_started so it can initialise alongside
	// siblings loaded at launch.
	a.pluginHost.Fire("on:app_started", nil)

	return nil
}

// GetPluginSettings returns the persisted settings blob for the named
// plugin, or nil if none exist. The returned bytes are the opaque JSON
// body the plugin authored — the frontend auto-renders against the
// manifest's settings schema.
func (a *App) GetPluginSettings(name string) json.RawMessage {
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return nil
	}
	return sc.PluginSettings[name]
}

// UpdatePluginSettings persists a new settings blob for the named plugin
// and calls settings.apply on the running subprocess so it can validate
// + react. Requires FIDO2 re-auth — plugin settings are HMAC-covered.
func (a *App) UpdatePluginSettings(name string, settings json.RawMessage, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return fmt.Errorf("must be unlocked to change plugin settings")
	}

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return fmt.Errorf("loading secure config: %w", err)
	}

	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 authorization required: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	// Normalise: treat empty/nil as absence so the HMAC stays stable.
	if sc.PluginSettings == nil {
		sc.PluginSettings = map[string]json.RawMessage{}
	}
	if len(settings) == 0 {
		delete(sc.PluginSettings, name)
	} else {
		sc.PluginSettings[name] = settings
	}

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return err
	}
	if err := a.saveSignedSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("saving secure config: %w", err)
	}
	a.secureCfg = sc

	// Best-effort push to the running plugin subprocess. If the plugin
	// crashed the reconfig just logs — settings are already persisted.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.pluginHost.Reconfigure(ctx, name, settings); err != nil {
		log.Printf("monban: plugin %s settings.apply: %v", name, err)
	}
	a.pluginHost.Fire("on:settings_changed", map[string]any{
		"pluginName": name,
	})

	return nil
}

// UninstallPlugin terminates the plugin subprocess, removes its directory
// from ~/.config/monban/plugins/, and clears its settings from
// SecureConfig. Requires FIDO2 re-auth.
func (a *App) UninstallPlugin(name string, pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return fmt.Errorf("must be unlocked to uninstall plugins")
	}

	// Find the plugin's dir before unload (unload forgets it).
	var dir string
	for _, ps := range a.pluginHost.List() {
		if ps.Name == name {
			dir = ps.Dir
			break
		}
	}
	if dir == "" {
		return fmt.Errorf("plugin %q not loaded", name)
	}

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return fmt.Errorf("loading secure config: %w", err)
	}

	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 authorization required: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	unloadCtx, unloadCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer unloadCancel()
	_ = a.pluginHost.Unload(unloadCtx, name)

	monban.UnlockConfigDir()
	rmErr := removeAll(dir)
	monban.LockConfigDir()
	if rmErr != nil {
		return fmt.Errorf("removing plugin dir: %w", rmErr)
	}

	if sc.PluginSettings != nil {
		delete(sc.PluginSettings, name)
	}

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

func (a *App) SetWindow(w *application.WebviewWindow) {
	a.window = w
}

// ExitFullscreen switches the window to normal mode after unlock.
func (a *App) ExitFullscreen() {
	exitKioskMode()
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
		enterKioskMode()
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
