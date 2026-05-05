package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// --- Types ---

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
	masterSecret *monban.MasterSecret // in-memory only, zeroed on lock
	encKey       []byte                // derived file encryption key, zeroed on lock
	wailsApp     *application.App
	window       *application.WebviewWindow
	pluginHost   *plugin.Host

	// Pending plugin-initiated PIN+touch prompts. Keyed by request id so
	// the frontend can respond/cancel via RespondPluginPinTouch without
	// needing a stateful RPC channel of its own. pinTouchMeta mirrors
	// pinTouchPending but stores the user-visible labels so the
	// frontend can query them on cold start via GetPendingPluginPinTouch.
	pinTouchMu      sync.Mutex
	pinTouchPending map[string]chan pinTouchReply
	pinTouchMeta    map[string]pinTouchMeta
}

type pinTouchReply struct {
	ok  bool
	err error
}

type pinTouchMeta struct {
	title    string
	subtitle string
}

// PluginPinTouchRequest is emitted to the frontend when a plugin asks
// the host to prompt for PIN + touch. The frontend shows a PinAuth
// dialog and responds via RespondPluginPinTouch(id, pin).
type PluginPinTouchRequest struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
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

// --- Package-level vars ---

// removeAll is a thin wrapper so we can swap it in tests without touching
// the filesystem under HOME.
var removeAll = os.RemoveAll

// --- Public functions ---

func NewApp() *App {
	a := &App{
		locked:          true,
		pinTouchPending: map[string]chan pinTouchReply{},
		pinTouchMeta:    map[string]pinTouchMeta{},
	}
	a.pluginHost = plugin.NewHost(plugin.HostConfig{
		PluginsDir:         filepath.Join(monban.ConfigDir(), "plugins"),
		HostVersion:        Version,
		LoadPluginSettings: loadPluginSettingsFromConfig,
		OnRequestPinTouch: func(ctx context.Context, req plugin.PinTouchRequest) (*plugin.PinTouchResult, error) {
			return a.handlePluginPinTouch(ctx, req)
		},
		OnAuthAssertWithPin: func(ctx context.Context, pin string) (bool, error) {
			return a.handlePluginAssertWithPin(ctx, pin)
		},
	})
	return a
}

func (a *App) SetWindow(w *application.WebviewWindow) {
	a.window = w
}

func (a *App) SetWailsApp(app *application.App) {
	a.wailsApp = app
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

// ResizeWindow resizes the window to fit content.
func (a *App) ResizeWindow(width, height int) {
	if a.window != nil {
		a.window.SetSize(width, height)
	}
}

// HideWindow hides Monban's window and drops it from the Dock. Used
// after a plugin-initiated authorization completes — the user wasn't
// actively using Monban's UI, they just needed to authenticate, so
// we should get out of their way. They can bring Monban back via the
// system-tray menu.
func (a *App) HideWindow() {
	if a.window == nil {
		return
	}
	invokeSync(func() {
		a.window.Hide()
	})
	hideFromDock()
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
func (a *App) InstallPlugin(name, pin string) (retErr error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() {
		if retErr != nil {
			log.Printf("monban: install plugin %q failed: %v", name, retErr)
		}
	}()

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
	defer masterSecret.Zero()

	pluginsDir := filepath.Join(monban.ConfigDir(), "plugins")
	installer := plugin.NewInstaller(pluginsDir)
	installer.VerifyInstallReceipt = verifyInstallReceipt
	// H5 + N14: plugins with install_pkg will run root code via
	// Installer.app. Require a second FIDO2 touch right before that
	// happens, AND surface a frontend overlay so the user understands
	// what the touch authorises. Without the overlay the second
	// assertion is a silent touch the user thinks is part of the
	// first — technically a second FIDO2 proof but not informed
	// consent.
	installer.ConfirmInstallPkg = func(_ context.Context, m *plugin.Manifest) error {
		if a.window != nil {
			a.window.EmitEvent("install:second-touch-required", map[string]string{
				"pluginName":  m.Name,
				"displayName": m.DisplayTitle(),
			})
			defer a.window.EmitEvent("install:second-touch-complete", map[string]string{
				"pluginName": m.Name,
			})
		}
		confirmSecret, rerr := a.fidoReauth(pin)
		if rerr != nil {
			return fmt.Errorf("second touch required before %s installer runs: %w", m.Name, rerr)
		}
		confirmSecret.Zero()
		return nil
	}

	// GUI Installer.app walks the user through screens; allow plenty
	// of time. The outer timeout also protects against a stuck
	// Installer.app process.
	monban.UnlockConfigDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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

	return a.withAuthConfigMutation(pin, nil,
		func(sc *monban.SecureConfig, _ *monban.MasterSecret, _ []byte) error {
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
			return nil
		},
	)
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
	// L1: hard cap on the settings blob before it touches disk or the
	// host→plugin pipe. 64 KB is comfortably larger than any sane
	// settings schema and small enough that a pathological write
	// can't DoS the host.
	const maxSettingsBytes = 64 * 1024
	if len(settings) > maxSettingsBytes {
		return fmt.Errorf("plugin settings too large: %d bytes (max %d)", len(settings), maxSettingsBytes)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return fmt.Errorf("must be unlocked to change plugin settings")
	}

	err := a.withAuthConfigMutation(pin, nil,
		func(sc *monban.SecureConfig, _ *monban.MasterSecret, _ []byte) error {
			// Normalise: treat empty/nil as absence so the HMAC stays stable.
			if sc.PluginSettings == nil {
				sc.PluginSettings = map[string]json.RawMessage{}
			}
			if len(settings) == 0 {
				delete(sc.PluginSettings, name)
			} else {
				sc.PluginSettings[name] = settings
			}
			return nil
		},
	)
	if err != nil {
		return err
	}

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

// GetPendingPluginPinTouch returns the oldest outstanding pin-touch
// request, or nil if none is pending. Called by the frontend on mount
// to cover the cold-start case where Monban was launched by the
// SecurityAgent bundle (open -a Monban) because of an admin-gate
// prompt — the plugin:pin-touch-request event fires before React
// subscribes, so without this poll the dialog would never appear.
func (a *App) GetPendingPluginPinTouch() *PluginPinTouchRequest {
	a.pinTouchMu.Lock()
	defer a.pinTouchMu.Unlock()
	// There's only ever one at a time in practice (the UI blocks on
	// the first), so this picks whichever iteration lands first.
	for id, meta := range a.pinTouchMeta {
		return &PluginPinTouchRequest{ID: id, Title: meta.title, Subtitle: meta.subtitle}
	}
	return nil
}

// RespondPluginPinTouch is called by the frontend when the user submits
// a PIN for a plugin-initiated request. Performs a FIDO2 assertion with
// the given PIN and signals the waiting goroutine.
func (a *App) RespondPluginPinTouch(id string, pin string) error {
	a.pinTouchMu.Lock()
	reply, ok := a.pinTouchPending[id]
	a.pinTouchMu.Unlock()
	if !ok {
		return fmt.Errorf("no pending request with id %q", id)
	}

	// fidoReauth wants a.mu; we also use it for the reply.
	a.mu.Lock()
	masterSecret, err := a.fidoReauth(pin)
	a.mu.Unlock()
	if err != nil {
		reply <- pinTouchReply{ok: false, err: err}
		return err
	}
	masterSecret.Zero()

	reply <- pinTouchReply{ok: true}
	return nil
}

// CancelPluginPinTouch is called when the user dismisses a plugin PIN
// prompt. Signals the waiting goroutine so the plugin gets a cancel
// response promptly.
func (a *App) CancelPluginPinTouch(id string) {
	a.pinTouchMu.Lock()
	reply, ok := a.pinTouchPending[id]
	a.pinTouchMu.Unlock()
	if !ok {
		return
	}
	reply <- pinTouchReply{ok: false, err: fmt.Errorf("cancelled by user")}
}

// --- Private methods ---

// handlePluginAssertWithPin performs a FIDO2 assertion with a PIN that
// a plugin helper already collected (e.g. from /dev/tty during a
// terminal sudo). Blocks until the user touches their security key.
// Returns true only on a successful assertion that unwraps to the
// correct master secret.
func (a *App) handlePluginAssertWithPin(_ context.Context, pin string) (bool, error) {
	a.mu.Lock()
	masterSecret, err := a.fidoReauth(pin)
	a.mu.Unlock()
	if err != nil {
		return false, err
	}
	masterSecret.Zero()
	return true, nil
}

// handlePluginPinTouch is invoked when a plugin's helper asks the host
// to prompt the user for PIN + touch (e.g. the admin-gate sudo flow).
// Emits an event to the frontend, blocks until the user responds or
// the context cancels, returns the result to the plugin.
func (a *App) handlePluginPinTouch(ctx context.Context, req plugin.PinTouchRequest) (*plugin.PinTouchResult, error) {
	id := randomID()
	reply := make(chan pinTouchReply, 1)

	a.pinTouchMu.Lock()
	a.pinTouchPending[id] = reply
	a.pinTouchMeta[id] = pinTouchMeta{title: req.Title, subtitle: req.Subtitle}
	a.pinTouchMu.Unlock()
	defer func() {
		a.pinTouchMu.Lock()
		delete(a.pinTouchPending, id)
		delete(a.pinTouchMeta, id)
		a.pinTouchMu.Unlock()
	}()

	if a.window == nil {
		return nil, fmt.Errorf("no window available to prompt")
	}
	// Exit kiosk/fullscreen if we're forced-auth locked; plugin auth is
	// a separate concern from Monban's own unlock state and we don't
	// want the regular lock screen to hijack the window.
	a.ExitFullscreen()

	// Emit the event FIRST, then sleep briefly before showing the
	// window. This is the 0.4.0 fix for a visible flash: with the
	// window still hidden, React has time to receive the event (or
	// resolve its cold-start pending-request poll) and render the
	// authorize view. When we Show() a moment later, the correct view
	// is already on screen — the user never sees the lock/admin screen
	// flicker underneath.
	a.window.EmitEvent("plugin:pin-touch-request", PluginPinTouchRequest{
		ID:       id,
		Title:    req.Title,
		Subtitle: req.Subtitle,
	})
	time.Sleep(200 * time.Millisecond)
	showInDock()
	invokeSync(func() {
		a.window.Show()
		a.window.Focus()
	})

	select {
	case r := <-reply:
		if r.err != nil {
			return nil, r.err
		}
		return &plugin.PinTouchResult{OK: r.ok}, nil
	case <-ctx.Done():
		// Let the UI know we timed out so it can dismiss the dialog.
		a.window.EmitEvent("plugin:pin-touch-cancelled", map[string]string{"id": id})
		return nil, ctx.Err()
	}
}

// withAuthConfigMutation runs a FIDO2-authenticated mutation against the
// secure config. Caller must hold a.mu.
//
//  1. Loads SecureConfig fresh from disk.
//  2. Calls prepare(sc) if non-nil (validation + work using a.encKey is OK).
//  3. Performs FIDO2 re-auth, deriving a fresh master secret.
//  4. Calls apply(sc, masterSecret, hmacSalt) if non-nil.
//  5. Increments counter, signs, saves, writes encrypted counter.
//  6. Updates a.secureCfg pointer to the saved config.
//
// The fresh master secret is zeroed before return.
func (a *App) withAuthConfigMutation(
	pin string,
	prepare func(sc *monban.SecureConfig) error,
	apply func(sc *monban.SecureConfig, masterSecret *monban.MasterSecret, hmacSalt []byte) error,
) error {
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return fmt.Errorf("loading secure config: %w", err)
	}

	if prepare != nil {
		if err := prepare(sc); err != nil {
			return err
		}
	}

	masterSecret, err := a.fidoReauth(pin)
	if err != nil {
		return fmt.Errorf("FIDO2 authorization required: %w", err)
	}
	defer masterSecret.Zero()

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return err
	}

	if apply != nil {
		if err := apply(sc, masterSecret, hmacSalt); err != nil {
			return err
		}
	}

	if err := a.saveSignedSecureConfig(sc, masterSecret, hmacSalt); err != nil {
		return fmt.Errorf("saving secure config: %w", err)
	}

	a.secureCfg = sc
	return nil
}

// saveSignedSecureConfig increments the counter, signs the config, saves it,
// and writes the encrypted counter file. Caller must hold a.mu and ensure
// masterSecret and hmacSalt are valid.
func (a *App) saveSignedSecureConfig(sc *monban.SecureConfig, masterSecret *monban.MasterSecret, hmacSalt []byte) error {
	sc.ConfigCounter++

	if err := masterSecret.SignConfig(sc, hmacSalt); err != nil {
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
		encKey, err = masterSecret.FileEncKey(hmacSalt)
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
// The caller is responsible for Zero()-ing the returned secret.
// Must be called with a.mu held.
func (a *App) fidoReauth(pin string) (*monban.MasterSecret, error) {
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
		masterSecret.Zero()
		return nil, fmt.Errorf("assertion verification failed: %w", err)
	}

	return masterSecret, nil
}

// --- Private package-level helpers ---

// randomID returns a short random hex id unique enough for in-memory
// correlation.
func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// verifyInstallReceipt decides whether an install_pkg run completed
// successfully. Installer.app exiting cleanly doesn't mean the install
// actually happened — the user might have clicked Cancel. Plugins that
// ship an install_pkg are expected to drop a timestamp file at a
// known path once their postinstall finishes. Admin-gate uses
// /Library/Application Support/Monban/<name>-installed.
func verifyInstallReceipt(_ context.Context, m *plugin.Manifest) error {
	if m.InstallPkg == "" {
		return nil
	}
	marker := filepath.Join(
		"/Library/Application Support/Monban",
		m.Name+"-installed",
	)
	info, err := os.Stat(marker)
	if err != nil {
		return fmt.Errorf("receipt %q not found (user cancelled or postinstall failed): %w",
			marker, err)
	}
	if time.Since(info.ModTime()) > 10*time.Minute {
		return fmt.Errorf("receipt %q is stale (modified %s ago) — install did not run this time",
			marker, time.Since(info.ModTime()).Round(time.Second))
	}
	return nil
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
