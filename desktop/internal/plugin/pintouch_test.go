package plugin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pinTouchMockPlugin is a one-shot plugin that fires a request_pin_touch
// right after hello, then echoes the result back on stderr so the test
// can observe it.
const pinTouchMockSrc = `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type msg struct {
	ID     string          ` + "`json:\"id,omitempty\"`" + `
	Type   string          ` + "`json:\"type\"`" + `
	Method string          ` + "`json:\"method,omitempty\"`" + `
	Params json.RawMessage ` + "`json:\"params,omitempty\"`" + `
	Result json.RawMessage ` + "`json:\"result,omitempty\"`" + `
}

func main() {
	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var in msg
		if err := json.Unmarshal(line, &in); err != nil {
			continue
		}
		switch in.Method {
		case "hello":
			res, _ := json.Marshal(map[string]any{
				"name": "mock-pin-touch", "version": "0.1.0",
				"hooks": []string{}, "provides": []any{}, "ready": true,
			})
			out, _ := json.Marshal(msg{ID: in.ID, Type: "response", Result: res})
			_, _ = w.Write(append(out, '\n'))
			_ = w.Flush()

			// Fire a request_pin_touch to the host.
			params, _ := json.Marshal(map[string]string{
				"title": "System Settings", "subtitle": "Approve",
			})
			req, _ := json.Marshal(msg{
				ID: "pt-1", Type: "request",
				Method: "request_pin_touch", Params: params,
			})
			_, _ = w.Write(append(req, '\n'))
			_ = w.Flush()
		case "shutdown":
			return
		default:
			// Host responses — report result to stderr for the test
			// to observe.
			if in.ID == "pt-1" {
				fmt.Fprintf(os.Stderr, "PIN_TOUCH_RESULT type=%s result=%s\n", in.Type, string(in.Result))
				if in.Type == "error" {
					fmt.Fprintln(os.Stderr, "PIN_TOUCH_ERROR")
				}
			}
		}
	}
}
`

func buildPinTouchMock(t *testing.T, binDir string) string {
	t.Helper()
	srcDir := filepath.Join(t.TempDir(), "pintouchmock")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(pinTouchMockSrc), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module pintouchmock\n\ngo 1.21\n"), 0644); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(binDir, "pintouchmock")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = srcDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build pintouchmock: %v\n%s", err, out)
	}
	return binPath
}

func installPinTouchMock(t *testing.T, pluginsDir string, priv ed25519.PrivateKey) {
	t.Helper()
	pluginDir := filepath.Join(pluginsDir, "mock-pin-touch")
	if err := os.MkdirAll(filepath.Join(pluginDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	buildPinTouchMock(t, filepath.Join(pluginDir, "bin"))
	// Rename to the manifest-declared name so the host spawns it.
	_ = os.Rename(
		filepath.Join(pluginDir, "bin", "pintouchmock"),
		filepath.Join(pluginDir, "bin", "mock"),
	)

	plat := CurrentPlatform()
	m := map[string]any{
		"name":       "mock-pin-touch",
		"version":    "0.1.0",
		"monban_api": HostAPIVersion,
		"platforms":  []string{plat},
		"kind":       []string{"observer"},
		"binary":     map[string]string{plat: "bin/mock"},
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	mp := filepath.Join(pluginDir, "manifest.json")
	if err := os.WriteFile(mp, raw, 0644); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, raw)
	if err := os.WriteFile(mp+".sig", sig, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRequestPinTouchInvokesCallback(t *testing.T) {
	priv := withTempKey(t)
	pluginsDir := t.TempDir()
	installPinTouchMock(t, pluginsDir, priv)

	var calls atomic.Int64
	var gotTitle, gotSubtitle string

	h := NewHost(HostConfig{
		PluginsDir:  pluginsDir,
		HostVersion: "0.0.0-test",
		Logger:      log.New(&bytes.Buffer{}, "", 0),
		OnRequestPinTouch: func(_ context.Context, req PinTouchRequest) (*PinTouchResult, error) {
			calls.Add(1)
			gotTitle = req.Title
			gotSubtitle = req.Subtitle
			return &PinTouchResult{OK: true, UID: 501, Username: "alice"}, nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		h.Shutdown(sctx)
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("OnRequestPinTouch was never invoked")
	}
	// Host prepends "[<plugin-display-name>] " to the plugin-supplied
	// title so the UI always attributes a prompt to its source (M3).
	if !strings.Contains(gotTitle, "System Settings") {
		t.Errorf("title = %q, want to contain System Settings", gotTitle)
	}
	if !strings.HasPrefix(gotTitle, "[") {
		t.Errorf("title = %q, want plugin-name prefix", gotTitle)
	}
	if gotSubtitle != "Approve" {
		t.Errorf("subtitle = %q, want Approve", gotSubtitle)
	}
}

func TestRequestPinTouchErrorRepliedAsError(t *testing.T) {
	priv := withTempKey(t)
	pluginsDir := t.TempDir()
	installPinTouchMock(t, pluginsDir, priv)

	stderr := &syncBuf{}
	h := NewHost(HostConfig{
		PluginsDir:  pluginsDir,
		HostVersion: "0.0.0-test",
		Logger:      log.New(stderr, "", 0),
		OnRequestPinTouch: func(context.Context, PinTouchRequest) (*PinTouchResult, error) {
			return nil, errors.New("user cancelled")
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		h.Shutdown(sctx)
	})

	// The mock echoes "PIN_TOUCH_ERROR" on stderr when it gets an error
	// response back. The host forwards stderr into the logger.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stderr.String(), "PIN_TOUCH_ERROR") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("plugin never saw error reply; log:\n%s", stderr.String())
}

func TestRequestPinTouchUnconfiguredRepliesError(t *testing.T) {
	priv := withTempKey(t)
	pluginsDir := t.TempDir()
	installPinTouchMock(t, pluginsDir, priv)

	stderr := &syncBuf{}
	h := NewHost(HostConfig{
		PluginsDir:  pluginsDir,
		HostVersion: "0.0.0-test",
		Logger:      log.New(stderr, "", 0),
		// OnRequestPinTouch: nil — host should reply with an error.
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		h.Shutdown(sctx)
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stderr.String(), "PIN_TOUCH_ERROR") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected plugin to receive error reply when callback absent; log:\n%s", stderr.String())
}

// syncBuf is a goroutine-safe bytes.Buffer adapter. The host's stderr
// forwarder and the test's observer run in different goroutines.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

