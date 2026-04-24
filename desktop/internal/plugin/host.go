package plugin

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// --- Types ---

// HelloResult is what a plugin returns to the host's initial hello request.
type HelloResult struct {
	Name     string        `json:"name"`
	Version  string        `json:"version"`
	Hooks    []string      `json:"hooks,omitempty"`
	Provides []ProvideSpec `json:"provides,omitempty"`
	Ready    bool          `json:"ready"`
}

// helloParams is what the host sends as hello's params.
type helloParams struct {
	HostVersion string          `json:"host_version"`
	HostAPI     string          `json:"host_api"`
	Config      json.RawMessage `json:"config,omitempty"`
}

// Plugin is a single running plugin subprocess with its RPC codec and the
// pending-request map for correlating responses.
type Plugin struct {
	Manifest *Manifest
	Dir      string

	cmd    *exec.Cmd
	codec  *Codec
	hello  *HelloResult
	cancel context.CancelFunc

	mu          sync.Mutex
	pending     map[string]chan *Message
	closed      bool
	terminating bool // set true when the host is intentionally shutting the plugin down

	// M3: rate-limit state for request_pin_touch. Without this a
	// rogue/compromised plugin can spam the user with lookalike
	// "Approve X" dialogs to train click-through habits or phish.
	pinPromptMu       sync.Mutex
	pinPromptLastAt   time.Time
	pinPromptLastBody string

	// N11: per-plugin cooldown between auth.assert_with_pin calls.
	// Wrong PINs submitted via this RPC decrement the security key's
	// hardware retry counter, so a buggy or compromised plugin could
	// (in the absence of rate-limiting) brick the key in milliseconds.
	// Paired with the global consecutive-failure lockout in Host.
	assertPinMu     sync.Mutex
	assertPinLastAt time.Time

	// N12: token-bucket rate limit for log-notify messages so a
	// plugin cannot drown the host log (local DoS, storage burn).
	// Leaky bucket: refilled on consume proportional to elapsed time.
	logBucketMu     sync.Mutex
	logBucketTokens float64
	logBucketLastAt time.Time
}

// HostConfig is the configuration handed to NewHost.
type HostConfig struct {
	// PluginsDir is the root directory containing one subdirectory per
	// installed plugin (e.g. ~/.config/monban/plugins/).
	PluginsDir string
	// HostVersion is the Monban app version reported to plugins.
	HostVersion string
	// Logger is used for host-side log lines; nil falls back to the std
	// logger.
	Logger *log.Logger
	// LoadPluginSettings, if set, returns the persisted settings blob for
	// the named plugin. Called once per plugin during Start() and the
	// result is passed as the hello handshake's config field. Return
	// nil for plugins with no stored settings.
	LoadPluginSettings func(name string) json.RawMessage
	// OnRequestPinTouch, if set, is invoked when a plugin sends the
	// request_pin_touch RPC — typically when the plugin's own helper
	// (e.g. the admin-gate SecurityAgent plugin) needs the Monban UI
	// to prompt the user for PIN + touch. The host blocks the plugin's
	// RPC until this returns. Return an error to fail the plugin's
	// request.
	OnRequestPinTouch func(ctx context.Context, req PinTouchRequest) (*PinTouchResult, error)
	// OnAuthAssertWithPin, if set, is invoked when a plugin sends the
	// auth.assert_with_pin RPC — the terminal-sudo path where the
	// plugin has already collected a PIN from /dev/tty. Host performs
	// the FIDO2 assertion (which blocks until the user touches their
	// security key) and returns success/failure.
	OnAuthAssertWithPin func(ctx context.Context, pin string) (bool, error)
}

// PinTouchRequest is the parameters of a plugin-initiated PIN+touch
// request. Shown to the user so they know which plugin is asking and
// why before they authenticate.
type PinTouchRequest struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
}

// PinTouchResult is the response sent back to a plugin after a
// request_pin_touch. UID/Username are populated for plugins like the
// admin-gate helper that need to know which user was authenticated.
type PinTouchResult struct {
	OK       bool   `json:"ok"`
	UID      int    `json:"uid,omitempty"`
	Username string `json:"username,omitempty"`
}

// Host manages the set of loaded plugin subprocesses.
type Host struct {
	cfg HostConfig
	log *log.Logger

	// lifetimeCtx scopes every spawned plugin subprocess to the Host's
	// own lifetime — cancelled only by Shutdown. This is deliberately
	// separate from the ctx callers pass into Start/LoadOne, which is
	// only used for the hello-handshake timeout. Tying subprocesses to
	// the caller's ctx would kill them as soon as the calling function
	// returned (e.g. App.InstallPlugin's 15 s loadCtx firing its
	// deferred cancel right after a successful install).
	lifetimeCtx    context.Context
	lifetimeCancel context.CancelFunc

	mu      sync.Mutex
	plugins map[string]*Plugin

	// N11: global, cross-plugin lockout state for auth.assert_with_pin.
	// Protects the security key from rapid-drain attacks initiated by
	// a malicious/buggy signed plugin. After assertFailureThreshold
	// consecutive failures across *any* plugin we refuse further
	// auth.assert_with_pin calls until the user proves possession
	// through the main UI unlock (which calls NotifyUserUnlockSucceeded
	// to reset). See the thread around N11 for the full design note.
	assertStateMu  sync.Mutex
	assertFailures int
	assertLocked   bool
}

// PluginStatus is a read-only snapshot of a loaded plugin for UI/API use.
type PluginStatus struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"display_name"`
	Version     string          `json:"version"`
	Description string          `json:"description,omitempty"`
	Kind        []string        `json:"kind"`
	Hooks       []string        `json:"hooks,omitempty"`
	Settings    json.RawMessage `json:"settings,omitempty"`
	Dir         string          `json:"dir"`
	Loaded      bool            `json:"loaded"`
}

// --- Constants ---

// Thresholds for the N11 cross-plugin assert-with-pin lockout. Values
// are deliberately conservative: 2 consecutive failures leaves 1
// hardware PIN retry of headroom before the CTAP2 soft-lock kicks in
// (3-per-cycle), and 30s between calls prevents rapid drain of the
// 8-retry lifetime counter.
const (
	assertFailureThreshold = 2
	assertPinMinInterval   = 30 * time.Second
)

// Log-notify rate-limit parameters. Burst capacity tolerates chatty
// startup lines; steady-state rate blocks sustained spam.
const (
	logBucketRatePerSec = 20.0
	logBucketCapacity   = 100.0
)

// pinPromptMinInterval is the floor between any two request_pin_touch
// prompts from the same plugin. Tight enough that legitimate multi-step
// flows aren't annoying, loose enough to kill spam attempts.
const pinPromptMinInterval = 5 * time.Second

// pinPromptDuplicateCooldown is the extra cooldown when a plugin sends
// a prompt with the same title+subtitle back-to-back — the exact shape
// of a "train the user to click through" attack.
const pinPromptDuplicateCooldown = 30 * time.Second

// envAllowlist is the closed set of host-env variables propagated into
// a plugin subprocess. Intentionally small — new variables must be
// added here explicitly. Must never include DYLD_*, LD_*,
// DYLD_INSERT_LIBRARIES, LD_PRELOAD, LD_LIBRARY_PATH, or any other
// dynamic-loader injection channel; those classes of variables are
// implicitly denied by not being in this list. L5: keep the allowlist
// tight so a future contributor can't accidentally widen it.
var envAllowlist = []string{"PATH", "HOME", "TMPDIR"}

// --- Public functions ---

// NewHost constructs a Host. It does not spawn any plugins yet.
func NewHost(cfg HostConfig) *Host {
	lg := cfg.Logger
	if lg == nil {
		lg = log.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Host{
		cfg:            cfg,
		log:            lg,
		lifetimeCtx:    ctx,
		lifetimeCancel: cancel,
		plugins:        map[string]*Plugin{},
	}
}

// List returns a snapshot of every loaded plugin.
func (h *Host) List() []PluginStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]PluginStatus, 0, len(h.plugins))
	for _, p := range h.plugins {
		out = append(out, PluginStatus{
			Name:        p.Manifest.Name,
			DisplayName: p.Manifest.DisplayTitle(),
			Version:     p.Manifest.Version,
			Description: p.Manifest.Description,
			Kind:        p.Manifest.Kind,
			Hooks:       p.Manifest.Hooks,
			Settings:    p.Manifest.Settings,
			Dir:         p.Dir,
			Loaded:      p.hello != nil && p.hello.Ready,
		})
	}
	return out
}

// Start scans PluginsDir for installed plugins, verifies each manifest
// signature, spawns the subprocess, and performs the hello handshake.
// Plugins that fail to load are logged and skipped — one bad plugin does
// not prevent others from loading.
func (h *Host) Start(ctx context.Context) error {
	entries, err := os.ReadDir(h.cfg.PluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read plugins dir %s: %w", h.cfg.PluginsDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(h.cfg.PluginsDir, e.Name())
		if err := h.loadOne(ctx, dir); err != nil {
			h.log.Printf("plugin: skip %s: %v", e.Name(), err)
		}
	}
	return nil
}

// LoadOne verifies and spawns a single plugin by directory name under
// PluginsDir. Used after an install so the new plugin is live without
// restarting the app.
func (h *Host) LoadOne(ctx context.Context, dirName string) error {
	return h.loadOne(ctx, filepath.Join(h.cfg.PluginsDir, dirName))
}

// Reconfigure sends a settings.apply request to the named plugin and
// blocks until it replies or the context is cancelled. Plugins may
// validate the settings and return an error in their response; callers
// should surface that error to the user rather than silently retrying.
func (h *Host) Reconfigure(ctx context.Context, name string, settings json.RawMessage) error {
	h.mu.Lock()
	p, ok := h.plugins[name]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("plugin %q not loaded", name)
	}
	_, err := p.request(ctx, "settings.apply", settings)
	return err
}

// Unload terminates and removes a single plugin. Used by uninstall: the
// caller still has to clean up the on-disk plugin dir.
func (h *Host) Unload(ctx context.Context, name string) error {
	h.mu.Lock()
	p, ok := h.plugins[name]
	if ok {
		delete(h.plugins, name)
	}
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("plugin %q not loaded", name)
	}
	_ = p.notify("shutdown", nil)
	if err := p.terminate(3 * time.Second); err != nil {
		h.log.Printf("plugin[%s]: unload: %v", name, err)
	}
	return nil
}

// Shutdown signals every loaded plugin to exit, waits for a grace period,
// then SIGKILLs stragglers.
func (h *Host) Shutdown(ctx context.Context) {
	h.mu.Lock()
	plugins := make([]*Plugin, 0, len(h.plugins))
	for _, p := range h.plugins {
		plugins = append(plugins, p)
	}
	h.plugins = map[string]*Plugin{}
	h.mu.Unlock()

	var wg sync.WaitGroup
	for _, p := range plugins {
		wg.Add(1)
		go func(p *Plugin) {
			defer wg.Done()
			// Notify-style shutdown, then wait up to 3s for exit, then kill.
			_ = p.notify("shutdown", nil)
			if err := p.terminate(3 * time.Second); err != nil {
				h.log.Printf("plugin[%s]: shutdown: %v", p.Manifest.Name, err)
			}
		}(p)
	}
	wg.Wait()

	// Stragglers attached via lifetimeCtx get signalled now in case
	// any plugin outlived terminate() somehow.
	h.lifetimeCancel()
}

// NotifyUserUnlockSucceeded is called by the host-level App when the
// user successfully unlocks Monban via the main UI. Clearing the
// lockout here (rather than on plugin success) is deliberate: a
// compromised plugin must not be able to reset its own kill-switch by
// generating a successful assertion against stolen credentials.
func (h *Host) NotifyUserUnlockSucceeded() {
	h.assertStateMu.Lock()
	defer h.assertStateMu.Unlock()
	h.assertFailures = 0
	h.assertLocked = false
}

// --- Private Host methods ---

func (h *Host) loadOne(ctx context.Context, dir string) error {
	manifestPath := filepath.Join(dir, "manifest.json")
	sigPath := manifestPath + ".sig"

	// H1: read manifest bytes once and verify+parse from the same buffer
	// to close the TOCTOU between VerifyFile and a second os.ReadFile.
	// A same-uid attacker could otherwise swap the file after signature
	// verification but before parse.
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read manifest sig: %w", err)
	}
	if err := Verify(raw, sig); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return err
	}
	if ok, reason := m.IsCompatibleAPI(); !ok {
		return fmt.Errorf("incompatible api: %s", reason)
	}
	if !m.SupportsCurrentPlatform() {
		return fmt.Errorf("unsupported platform %s (supported: %v)", CurrentPlatform(), m.Platforms)
	}

	// C5: resolve the manifest's binary path and verify it stays inside
	// the plugin directory. Without this, a signed manifest with
	// "binary": {"darwin-arm64": "../../../usr/bin/osascript"} escapes
	// the plugin sandbox — extractTarGz guards tarball entries the
	// same way; this is the parallel check on the manifest's own field.
	binRel := m.BinaryForCurrentPlatform()
	if binRel == "" {
		return fmt.Errorf("no binary entry for %s", CurrentPlatform())
	}
	binPath, err := resolvePluginPath(dir, binRel)
	if err != nil {
		return fmt.Errorf("binary: %w", err)
	}
	if _, err := os.Stat(binPath); err != nil {
		return fmt.Errorf("binary not found: %w", err)
	}

	// N2 production gate: release builds enforce binary_sha256
	// presence via the `production` build tag; dev builds tolerate
	// absence so iteration doesn't need build.sh on every change.
	wantHex := m.BinarySHA256ForCurrentPlatform()
	if wantHex == "" {
		if requireBinaryHashPin() {
			return fmt.Errorf("release build refuses to load plugin %q: manifest missing binary_sha256", m.Name)
		}
		h.log.Printf("plugin: %s manifest has no binary_sha256 — dev build, skipping swap-after-extract check (production builds will reject this)", m.Name)
	}

	h.mu.Lock()
	if _, exists := h.plugins[m.Name]; exists {
		h.mu.Unlock()
		return fmt.Errorf("duplicate plugin name %q", m.Name)
	}
	h.mu.Unlock()

	// Pass wantHex through to spawn: the actual SHA-256 verification
	// runs right before cmd.Start() so the window a same-uid attacker
	// has to swap the binary between verify and exec is as narrow as
	// possible (N3). The window cannot be closed entirely in Go —
	// execve() resolves the path at syscall time and there is no
	// portable fexecve — but minimizing it is still worthwhile.
	p, err := h.spawn(ctx, m, dir, binPath, wantHex)
	if err != nil {
		return err
	}

	h.mu.Lock()
	h.plugins[m.Name] = p
	h.mu.Unlock()

	h.log.Printf("plugin: loaded %s v%s (hooks=%v provides=%d)", m.Name, m.Version, p.hello.Hooks, len(p.hello.Provides))
	return nil
}

// spawn starts the plugin subprocess, wires the RPC codec, runs the hello
// handshake, and starts the read loop. On any error the subprocess is
// terminated and the error returned.
//
// The caller's ctx scopes only the hello handshake; the subprocess itself
// is tied to the Host's lifetimeCtx so it survives past the caller's
// deferred cancels.
func (h *Host) spawn(helloCtx context.Context, m *Manifest, dir, binPath, wantHex string) (*Plugin, error) {
	pluginCtx, cancel := context.WithCancel(h.lifetimeCtx)

	cmd := exec.CommandContext(pluginCtx, binPath)
	cmd.Dir = dir
	cmd.Env = sanitizedEnv(dir)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	// Hash verification immediately before exec (N3). The race between
	// this check and the syscall's path resolution cannot be closed in
	// portable Go, but keeping these two operations adjacent minimizes
	// the window.
	if wantHex != "" {
		if err := verifyFileSHA256(binPath, wantHex); err != nil {
			cancel()
			return nil, fmt.Errorf("binary hash: %w", err)
		}
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start: %w", err)
	}

	p := &Plugin{
		Manifest: m,
		Dir:      dir,
		cmd:      cmd,
		codec:    NewCodec(stdout, stdin),
		cancel:   cancel,
		pending:  map[string]chan *Message{},
	}

	// stderr forwarder
	go forwardStderr(stderr, m.Name, h.log)

	// read loop — started before hello so we can catch its response
	go h.readLoop(p)

	// hello handshake: bounded by whichever comes first — the caller's
	// ctx (15 s from App.InstallPlugin) or a generous 10 s ceiling.
	hsCtx, hsCancel := context.WithTimeout(helloCtx, 10*time.Second)
	defer hsCancel()

	result, err := h.hello(hsCtx, p)
	if err != nil {
		_ = p.terminate(2 * time.Second)
		return nil, fmt.Errorf("hello: %w", err)
	}
	p.hello = result

	if result.Name != m.Name {
		_ = p.terminate(2 * time.Second)
		return nil, fmt.Errorf("hello name %q does not match manifest %q", result.Name, m.Name)
	}
	if !result.Ready {
		_ = p.terminate(2 * time.Second)
		return nil, fmt.Errorf("plugin reported ready=false")
	}

	return p, nil
}

func (h *Host) hello(ctx context.Context, p *Plugin) (*HelloResult, error) {
	var cfg json.RawMessage
	if h.cfg.LoadPluginSettings != nil {
		cfg = h.cfg.LoadPluginSettings(p.Manifest.Name)
	}
	params, _ := json.Marshal(helloParams{
		HostVersion: h.cfg.HostVersion,
		HostAPI:     HostAPIVersion,
		Config:      cfg,
	})
	msg, err := p.request(ctx, "hello", params)
	if err != nil {
		return nil, err
	}
	var res HelloResult
	if err := json.Unmarshal(msg.Result, &res); err != nil {
		return nil, fmt.Errorf("decode hello result: %w", err)
	}
	return &res, nil
}

// readLoop processes inbound messages. Responses are routed to the pending
// request; notifies (log, ui.show_message, etc.) are handled inline.
func (h *Host) readLoop(p *Plugin) {
	defer func() {
		p.mu.Lock()
		closedByShutdown := p.terminating
		p.closed = true
		pend := p.pending
		p.pending = nil
		p.mu.Unlock()
		if !closedByShutdown {
			h.log.Printf("plugin[%s]: subprocess exited unexpectedly", p.Manifest.Name)
		}
		for _, ch := range pend {
			close(ch)
		}
	}()
	for {
		msg, err := p.codec.Read()
		if err != nil {
			if err != io.EOF {
				h.log.Printf("plugin[%s]: read error: %v", p.Manifest.Name, err)
			}
			return
		}
		switch msg.Type {
		case TypeResponse, TypeError:
			p.mu.Lock()
			ch, ok := p.pending[msg.ID]
			if ok {
				delete(p.pending, msg.ID)
			}
			p.mu.Unlock()
			if ok {
				ch <- msg
			} else {
				h.log.Printf("plugin[%s]: unknown response id %q", p.Manifest.Name, msg.ID)
			}
		case TypeNotify:
			h.handleNotify(p, msg)
		case TypeRequest:
			go h.handlePluginRequest(p, msg)
		default:
			h.log.Printf("plugin[%s]: unknown message type %q", p.Manifest.Name, msg.Type)
		}
	}
}

func (h *Host) handleNotify(p *Plugin, msg *Message) {
	switch msg.Method {
	case "log":
		var params struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(msg.Params, &params)
		// N12: rate-limit + sanitise every log-notify line. Without
		// the rate limit a plugin can drown the host log file as a
		// local DoS; without sanitisation it can smuggle control
		// chars or fake host-log prefixes. Sharing sanitizeStderrLine
		// with the stderr forwarder keeps the two channels aligned.
		if !p.allowLogNotify() {
			return
		}
		level := sanitizePromptField(params.Level, 16)
		h.log.Printf("plugin[%s] %s: %s", p.Manifest.Name, level, sanitizeStderrLine(params.Message))
	default:
		h.log.Printf("plugin[%s]: unhandled notify %q", p.Manifest.Name, msg.Method)
	}
}

// handlePluginRequest processes a plugin-initiated request. Runs in its
// own goroutine so the plugin's read loop isn't blocked while the host
// goes off to the UI thread. The reply is written back over the same
// codec, correlated by the request's ID.
func (h *Host) handlePluginRequest(p *Plugin, msg *Message) {
	switch msg.Method {
	case "request_pin_touch":
		h.handleRequestPinTouch(p, msg)
	case "auth.assert_with_pin":
		h.handleAuthAssertWithPin(p, msg)
	default:
		h.replyError(p, msg.ID, -32601, fmt.Sprintf("method %q not supported", msg.Method))
	}
}

func (h *Host) handleAuthAssertWithPin(p *Plugin, msg *Message) {
	// N13: capability gate — only plugins that declared
	// fido2_assert_with_pin in their signed manifest reach this
	// handler. Any other plugin (observer, generic auth_gate, etc.)
	// gets a "method not permitted" reply. This bounds the blast
	// radius of a malicious signed plugin: the RPC is not universal
	// ambient authority, it's an opt-in capability.
	if !p.Manifest.HasCapability(CapFIDOAssertWithPin) {
		h.replyError(p, msg.ID, -32601, "auth.assert_with_pin: missing capability "+CapFIDOAssertWithPin)
		return
	}
	if h.cfg.OnAuthAssertWithPin == nil {
		h.replyError(p, msg.ID, -32601, "auth.assert_with_pin not supported by host")
		return
	}
	var params struct {
		Pin string `json:"pin"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		h.replyError(p, msg.ID, -32602, "invalid params: "+err.Error())
		return
	}
	if params.Pin == "" {
		h.replyError(p, msg.ID, -32602, "pin required")
		return
	}

	// N11 gate 2: global consecutive-failure lockout. A successful
	// user unlock via the main UI clears this — see NotifyUserUnlockSucceeded.
	if h.assertLockedOut() {
		h.log.Printf("plugin[%s]: auth.assert_with_pin refused — locked out after %d consecutive plugin-initiated failures. User must unlock Monban to reset.", p.Manifest.Name, assertFailureThreshold)
		h.replyError(p, msg.ID, -32000, fmt.Sprintf("plugin auth locked out: %d consecutive failures. Unlock Monban to reset.", assertFailureThreshold))
		return
	}
	// N11 gate 1: per-plugin cooldown. Blocks a single plugin from
	// firing back-to-back wrong-PIN calls and burning the key's
	// hardware retry counter.
	if err := p.throttleAssertPin(); err != nil {
		h.log.Printf("plugin[%s]: auth.assert_with_pin throttled: %v", p.Manifest.Name, err)
		h.replyError(p, msg.ID, -32000, "rate limited")
		return
	}

	// FIDO2 assertion blocks waiting for the user to touch the key;
	// give it up to 2 minutes.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ok, err := h.cfg.OnAuthAssertWithPin(ctx, params.Pin)
	if err != nil {
		// err includes CTAP2 PIN-retry errors (wrong PIN, soft-lock).
		// Count these against the lockout threshold so a plugin that
		// emits garbage repeatedly hits the global gate before it can
		// drain the device-lifetime counter.
		h.recordAssertOutcome(false)
		h.replyError(p, msg.ID, -32000, err.Error())
		return
	}
	h.recordAssertOutcome(ok)
	resultBytes, _ := json.Marshal(map[string]bool{"ok": ok})
	_ = p.codec.Write(&Message{ID: msg.ID, Type: TypeResponse, Result: resultBytes})
}

func (h *Host) handleRequestPinTouch(p *Plugin, msg *Message) {
	if h.cfg.OnRequestPinTouch == nil {
		h.replyError(p, msg.ID, -32601, "request_pin_touch not supported by host")
		return
	}

	var req PinTouchRequest
	if len(msg.Params) > 0 {
		if err := json.Unmarshal(msg.Params, &req); err != nil {
			h.replyError(p, msg.ID, -32602, "invalid params: "+err.Error())
			return
		}
	}

	// M3: rate-limit + strip untrusted display fields before the
	// prompt reaches the UI.
	req.Title = sanitizePromptField(req.Title, 200)
	req.Subtitle = sanitizePromptField(req.Subtitle, 300)
	if err := p.allowPinTouchPrompt(req.Title, req.Subtitle); err != nil {
		h.log.Printf("plugin %s: pin_touch throttled: %v", p.Manifest.Name, err)
		h.replyError(p, msg.ID, -32000, "rate limited")
		return
	}
	// Force plugin name into the UI so user always knows who's asking.
	if req.Title == "" {
		req.Title = p.Manifest.DisplayTitle()
	} else {
		req.Title = "[" + p.Manifest.DisplayTitle() + "] " + req.Title
	}

	// Give the UI up to 2 minutes to collect a PIN+touch; anything
	// longer is almost certainly a stuck prompt.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := h.cfg.OnRequestPinTouch(ctx, req)
	if err != nil {
		h.replyError(p, msg.ID, -32000, err.Error())
		return
	}
	resultBytes, _ := json.Marshal(result)
	_ = p.codec.Write(&Message{ID: msg.ID, Type: TypeResponse, Result: resultBytes})
}

func (h *Host) replyError(p *Plugin, id string, code int, message string) {
	_ = p.codec.Write(&Message{
		ID:    id,
		Type:  TypeError,
		Error: &RPCError{Code: code, Message: message},
	})
}

// assertLockedOut reports whether the cross-plugin lockout is active.
// Once set, every plugin's auth.assert_with_pin is refused until the
// user proves possession via the main-UI unlock path, which calls
// NotifyUserUnlockSucceeded to clear the flag.
func (h *Host) assertLockedOut() bool {
	h.assertStateMu.Lock()
	defer h.assertStateMu.Unlock()
	return h.assertLocked
}

// recordAssertOutcome updates the global consecutive-failure counter
// based on an auth.assert_with_pin outcome. ok=true resets the counter
// (matches the YubiKey's own on-correct-PIN reset semantics). ok=false
// increments; hitting assertFailureThreshold latches the lockout until
// a user-initiated unlock clears it.
func (h *Host) recordAssertOutcome(ok bool) {
	h.assertStateMu.Lock()
	defer h.assertStateMu.Unlock()
	if ok {
		h.assertFailures = 0
		return
	}
	h.assertFailures++
	if h.assertFailures >= assertFailureThreshold {
		h.assertLocked = true
		h.log.Printf("plugin: auth.assert_with_pin global lockout engaged after %d consecutive failures — user must unlock Monban to reset", h.assertFailures)
	}
}

// --- Private Plugin methods ---

// request sends a request and blocks until the response arrives or the
// context is cancelled.
func (p *Plugin) request(ctx context.Context, method string, params json.RawMessage) (*Message, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("plugin closed")
	}
	id := randomID()
	ch := make(chan *Message, 1)
	p.pending[id] = ch
	p.mu.Unlock()

	msg := &Message{ID: id, Type: TypeRequest, Method: method, Params: params}
	if err := p.codec.Write(msg); err != nil {
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return nil, err
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errors.New("plugin closed before response")
		}
		if resp.Type == TypeError && resp.Error != nil {
			return nil, resp.Error
		}
		return resp, nil
	case <-ctx.Done():
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return nil, ctx.Err()
	}
}

// notify sends a fire-and-forget notify message.
func (p *Plugin) notify(method string, params any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	return p.codec.Write(&Message{Type: TypeNotify, Method: method, Params: raw})
}

// terminate waits grace for a clean exit, then kills.
func (p *Plugin) terminate(grace time.Duration) error {
	p.mu.Lock()
	p.terminating = true
	p.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
		p.cancel()
		return nil
	case <-time.After(grace):
		_ = p.cmd.Process.Kill()
		<-done
		p.cancel()
		return fmt.Errorf("killed after %s grace", grace)
	}
}

// allowLogNotify reports whether this plugin is allowed to emit
// another log-notify line right now. Leaky-bucket implementation:
// tokens refill at logBucketRatePerSec up to logBucketCapacity;
// each call consumes 1 token. Out-of-tokens → drop the message.
func (p *Plugin) allowLogNotify() bool {
	p.logBucketMu.Lock()
	defer p.logBucketMu.Unlock()
	now := time.Now()
	if p.logBucketLastAt.IsZero() {
		// First call: start with a full bucket.
		p.logBucketTokens = logBucketCapacity
	} else {
		elapsed := now.Sub(p.logBucketLastAt).Seconds()
		p.logBucketTokens += elapsed * logBucketRatePerSec
		if p.logBucketTokens > logBucketCapacity {
			p.logBucketTokens = logBucketCapacity
		}
	}
	p.logBucketLastAt = now
	if p.logBucketTokens < 1 {
		return false
	}
	p.logBucketTokens--
	return true
}

// throttleAssertPin enforces the per-plugin minimum interval between
// auth.assert_with_pin calls. Returns an error if the plugin is asking
// again too soon; caller surfaces "rate limited" to the plugin.
func (p *Plugin) throttleAssertPin() error {
	p.assertPinMu.Lock()
	defer p.assertPinMu.Unlock()
	now := time.Now()
	if !p.assertPinLastAt.IsZero() {
		if now.Sub(p.assertPinLastAt) < assertPinMinInterval {
			return fmt.Errorf("auth.assert_with_pin: must wait %s between calls", assertPinMinInterval)
		}
	}
	p.assertPinLastAt = now
	return nil
}

// allowPinTouchPrompt enforces M3's rate-limit. Returns an error if the
// prompt should be throttled (caller surfaces this to the plugin).
func (p *Plugin) allowPinTouchPrompt(title, subtitle string) error {
	p.pinPromptMu.Lock()
	defer p.pinPromptMu.Unlock()
	now := time.Now()
	if !p.pinPromptLastAt.IsZero() {
		since := now.Sub(p.pinPromptLastAt)
		body := title + "\x00" + subtitle
		if body == p.pinPromptLastBody && since < pinPromptDuplicateCooldown {
			return fmt.Errorf("duplicate prompt within %s cooldown", pinPromptDuplicateCooldown)
		}
		if since < pinPromptMinInterval {
			return fmt.Errorf("prompt within %s min interval", pinPromptMinInterval)
		}
	}
	p.pinPromptLastAt = now
	p.pinPromptLastBody = title + "\x00" + subtitle
	return nil
}

// --- Private package-level helpers ---

// forwardStderr tags each line a plugin writes to stderr with a fixed
// prefix that includes the plugin name, then strips non-printable bytes
// + clips length before routing to the host logger. M5 fix: without
// sanitisation a rogue plugin can emit crafted lines that masquerade
// as host output in log analysers / SIEMs.
func forwardStderr(r io.ReadCloser, name string, lg *log.Logger) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 16*1024)
	for scanner.Scan() {
		lg.Printf("plugin[%s] stderr: %s", name, sanitizeStderrLine(scanner.Text()))
	}
}

// sanitizeStderrLine strips control chars (incl. ANSI ESC, CR/NL) and
// clips to 1 KB so a single stderr line can't blow up a log file or
// render escape sequences into a tail -f'd terminal.
func sanitizeStderrLine(s string) string {
	const maxLen = 1024
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == 0x7f || r < 0x20 {
			out = append(out, '?')
			continue
		}
		out = append(out, r)
	}
	return string(out)
}

// sanitizedEnv builds a minimal environment for plugin subprocesses.
// Leaks nothing beyond envAllowlist + MONBAN_PLUGIN_DIR so plugins can
// locate their own payload files without inheriting host env.
func sanitizedEnv(pluginDir string) []string {
	env := []string{"MONBAN_PLUGIN_DIR=" + pluginDir}
	for _, k := range envAllowlist {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// sanitizePromptField strips characters that can misrepresent a
// prompt's displayed text from a plugin-supplied string, then clips
// to max runes. Covers:
//
//   - ASCII controls (incl. \n, \r, \t, ESC for ANSI)
//   - Unicode bidi overrides and embeddings (U+202A..202E, U+2066..2069)
//     that swap visual direction so a title renders reversed
//   - Zero-width characters (U+200B..200D, U+FEFF) that hide content
//   - LRM/RLM (U+200E/200F) that silently reshape neighbouring glyphs
//
// Without this a malicious plugin can render "Approve System Update"
// as a visually different message via a U+202E RTL override.
func sanitizePromptField(s string, max int) string {
	if s == "" {
		return s
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if isUnicodeFormattingControl(r) {
			continue
		}
		out = append(out, r)
		if len(out) >= max {
			break
		}
	}
	return strings.TrimSpace(string(out))
}

// isUnicodeFormattingControl reports whether r is a Unicode bidi/
// formatting character that can misrepresent the visual rendering of
// a string. Enumerated explicitly — these are a small closed set and
// pulling in unicode tables for category Cf would also strip benign
// code points like soft hyphen.
func isUnicodeFormattingControl(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, // zero-width space/non-joiner/joiner
		0x200E, 0x200F, // LRM, RLM
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // bidi embed/override
		0x2066, 0x2067, 0x2068, 0x2069, // isolate controls
		0xFEFF: // BOM / zero-width no-break space
		return true
	}
	return false
}

// verifyFileSHA256 returns nil if the file at path has the given hex
// SHA-256 digest. Case-insensitive on the hex comparison; lengths must
// match exactly. Used for the manifest-pinned binary-hash check.
func verifyFileSHA256(path, wantHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	gotHex := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(gotHex, wantHex) {
		return fmt.Errorf("mismatch: got %s, want %s", gotHex, wantHex)
	}
	return nil
}

// resolvePluginPath joins a manifest-declared relative path to the plugin
// directory and verifies the result stays inside that directory. Blocks
// C5 for any manifest field that names a payload file (binary,
// install_pkg, etc.) — without this, a signed manifest with e.g.
// "binary": "../../../usr/bin/osascript" would escape the plugin
// sandbox and have the host exec whatever the path points at.
func resolvePluginPath(dir, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty path")
	}
	// Manifest payload paths are always relative to the plugin dir.
	// An absolute-looking path is never what the author intended and
	// is the classic shape of an escape attempt.
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("manifest path %q must be relative", rel)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("abs plugin dir: %w", err)
	}
	absPath, err := filepath.Abs(filepath.Join(absDir, rel))
	if err != nil {
		return "", fmt.Errorf("abs payload path: %w", err)
	}
	r, err := filepath.Rel(absDir, absPath)
	if err != nil {
		return "", fmt.Errorf("rel payload path: %w", err)
	}
	if r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("manifest path %q escapes plugin dir", rel)
	}
	return absPath, nil
}
