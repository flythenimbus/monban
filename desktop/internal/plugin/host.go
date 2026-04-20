package plugin

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

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

	mu      sync.Mutex
	pending map[string]chan *Message
	closed  bool
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
}

// Host manages the set of loaded plugin subprocesses.
type Host struct {
	cfg HostConfig
	log *log.Logger

	mu      sync.Mutex
	plugins map[string]*Plugin
}

// NewHost constructs a Host. It does not spawn any plugins yet.
func NewHost(cfg HostConfig) *Host {
	lg := cfg.Logger
	if lg == nil {
		lg = log.Default()
	}
	return &Host{cfg: cfg, log: lg, plugins: map[string]*Plugin{}}
}

// PluginStatus is a read-only snapshot of a loaded plugin for UI/API use.
type PluginStatus struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Kind    []string `json:"kind"`
	Hooks   []string `json:"hooks,omitempty"`
	Dir     string   `json:"dir"`
	Loaded  bool     `json:"loaded"`
}

// List returns a snapshot of every loaded plugin.
func (h *Host) List() []PluginStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]PluginStatus, 0, len(h.plugins))
	for _, p := range h.plugins {
		out = append(out, PluginStatus{
			Name:    p.Manifest.Name,
			Version: p.Manifest.Version,
			Kind:    p.Manifest.Kind,
			Hooks:   p.Manifest.Hooks,
			Dir:     p.Dir,
			Loaded:  p.hello != nil && p.hello.Ready,
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

func (h *Host) loadOne(ctx context.Context, dir string) error {
	manifestPath := filepath.Join(dir, "manifest.json")
	sigPath := manifestPath + ".sig"

	if err := VerifyFile(manifestPath, sigPath); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
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

	binRel := m.BinaryForCurrentPlatform()
	if binRel == "" {
		return fmt.Errorf("no binary entry for %s", CurrentPlatform())
	}
	binPath := filepath.Join(dir, binRel)
	if _, err := os.Stat(binPath); err != nil {
		return fmt.Errorf("binary not found: %w", err)
	}

	h.mu.Lock()
	if _, exists := h.plugins[m.Name]; exists {
		h.mu.Unlock()
		return fmt.Errorf("duplicate plugin name %q", m.Name)
	}
	h.mu.Unlock()

	p, err := h.spawn(ctx, m, dir, binPath)
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
func (h *Host) spawn(ctx context.Context, m *Manifest, dir, binPath string) (*Plugin, error) {
	pluginCtx, cancel := context.WithCancel(ctx)

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

	// hello handshake with timeout
	helloCtx, helloCancel := context.WithTimeout(pluginCtx, 10*time.Second)
	defer helloCancel()

	result, err := h.hello(helloCtx, p)
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
	params, _ := json.Marshal(helloParams{
		HostVersion: h.cfg.HostVersion,
		HostAPI:     HostAPIVersion,
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
		p.closed = true
		pend := p.pending
		p.pending = nil
		p.mu.Unlock()
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
			// Plugin-initiated requests (e.g. ui.open_url) are not
			// implemented in P1 — log and ignore.
			h.log.Printf("plugin[%s]: unsupported request %q in P1", p.Manifest.Name, msg.Method)
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
		h.log.Printf("plugin[%s] %s: %s", p.Manifest.Name, params.Level, params.Message)
	default:
		h.log.Printf("plugin[%s]: unhandled notify %q (P1)", p.Manifest.Name, msg.Method)
	}
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
}

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

func forwardStderr(r io.ReadCloser, name string, lg *log.Logger) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lg.Printf("plugin[%s] stderr: %s", name, scanner.Text())
	}
}

// sanitizedEnv builds a minimal environment for plugin subprocesses.
// Leaks nothing beyond PATH, HOME, and MONBAN_PLUGIN_DIR so plugins can
// locate their own payload files without exposing host env.
func sanitizedEnv(pluginDir string) []string {
	env := []string{"MONBAN_PLUGIN_DIR=" + pluginDir}
	for _, k := range []string{"PATH", "HOME", "TMPDIR"} {
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
