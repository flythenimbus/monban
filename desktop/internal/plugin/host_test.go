package plugin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// installMockPlugin compiles testdata/mockplugin, writes a manifest matching
// the current platform, signs the manifest with priv, and places everything
// in <pluginsDir>/<name>/ ready to be loaded.
func installMockPlugin(t *testing.T, pluginsDir string, priv ed25519.PrivateKey, name string) {
	t.Helper()
	pluginDir := filepath.Join(pluginsDir, name)
	if err := os.MkdirAll(filepath.Join(pluginDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}

	// Compile the mock plugin binary into the plugin dir.
	_, testFile, _, _ := runtime.Caller(0)
	srcDir := filepath.Join(filepath.Dir(testFile), "testdata", "mockplugin")
	binOut := filepath.Join(pluginDir, "bin", "mock")

	cmd := exec.Command("go", "build", "-o", binOut, ".")
	cmd.Dir = srcDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build mockplugin: %v\n%s", err, out)
	}

	plat := CurrentPlatform()
	m := map[string]any{
		"name":       "mock-plugin",
		"version":    "0.1.0",
		"monban_api": HostAPIVersion,
		"platforms":  []string{plat},
		"kind":       []string{"observer"},
		"hooks":      []string{"on:app_started"},
		"binary":     map[string]string{plat: "bin/mock"},
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	manifestPath := filepath.Join(pluginDir, "manifest.json")
	if err := os.WriteFile(manifestPath, raw, 0644); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, raw)
	if err := os.WriteFile(manifestPath+".sig", sig, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestHostStartLoadsSignedPlugin(t *testing.T) {
	priv := withTempKey(t)

	pluginsDir := t.TempDir()
	installMockPlugin(t, pluginsDir, priv, "mock")

	var buf bytes.Buffer
	h := NewHost(HostConfig{
		PluginsDir:  pluginsDir,
		HostVersion: "0.0.0-test",
		Logger:      log.New(&buf, "", 0),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		h.Shutdown(shutdownCtx)
	})

	list := h.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 plugin loaded, got %d (log: %s)", len(list), buf.String())
	}
	if list[0].Name != "mock-plugin" || !list[0].Loaded {
		t.Errorf("unexpected plugin status: %+v", list[0])
	}
}

func TestHostRejectsTamperedManifest(t *testing.T) {
	priv := withTempKey(t)
	pluginsDir := t.TempDir()
	installMockPlugin(t, pluginsDir, priv, "mock")

	// Tamper with manifest after signing
	manifestPath := filepath.Join(pluginsDir, "mock", "manifest.json")
	data, _ := os.ReadFile(manifestPath)
	data = bytes.Replace(data, []byte("mock-plugin"), []byte("evil-plugin"), 1)
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	h := NewHost(HostConfig{
		PluginsDir:  pluginsDir,
		HostVersion: "0.0.0-test",
		Logger:      log.New(&buf, "", 0),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = h.Start(ctx)

	if len(h.List()) != 0 {
		t.Errorf("tampered plugin should not load; got %d loaded", len(h.List()))
	}
	if !strings.Contains(buf.String(), "signature") {
		t.Errorf("expected signature failure in log, got: %s", buf.String())
	}
}

func TestHostMissingPluginsDirIsOK(t *testing.T) {
	withTempKey(t)
	h := NewHost(HostConfig{PluginsDir: "/nonexistent/path/definitely-not-here"})
	if err := h.Start(context.Background()); err != nil {
		t.Errorf("missing plugins dir should not error, got %v", err)
	}
	if len(h.List()) != 0 {
		t.Errorf("expected 0 plugins, got %d", len(h.List()))
	}
}

func TestHostFireDeliversHookToSubscribedPlugin(t *testing.T) {
	priv := withTempKey(t)
	pluginsDir := t.TempDir()
	installMockPlugin(t, pluginsDir, priv, "mock")

	var mu sync.Mutex
	var buf bytes.Buffer
	h := NewHost(HostConfig{
		PluginsDir:  pluginsDir,
		HostVersion: "0.0.0-test",
		Logger:      log.New(logSyncWriter{mu: &mu, buf: &buf}, "", 0),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		h.Shutdown(shutdownCtx)
	})

	h.Fire("on:app_started", nil)

	// The mock logs "MOCK_HOOK_RECEIVED on:app_started" on stderr; the
	// host's stderr forwarder echoes it into the logger. Poll briefly.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := buf.String()
		mu.Unlock()
		if strings.Contains(got, "MOCK_HOOK_RECEIVED on:app_started") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	logOut := buf.String()
	mu.Unlock()
	t.Fatalf("hook never reached plugin stderr; log was:\n%s", logOut)
}

func TestHostDuplicateNameRejected(t *testing.T) {
	priv := withTempKey(t)
	pluginsDir := t.TempDir()
	installMockPlugin(t, pluginsDir, priv, "mock-a")
	installMockPlugin(t, pluginsDir, priv, "mock-b")

	var buf bytes.Buffer
	h := NewHost(HostConfig{
		PluginsDir:  pluginsDir,
		HostVersion: "0.0.0-test",
		Logger:      log.New(&buf, "", 0),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = h.Start(ctx)
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		h.Shutdown(shutdownCtx)
	})

	// Both plugins declare name "mock-plugin" in their hello. Second one
	// should be rejected as duplicate.
	if got := len(h.List()); got != 1 {
		t.Fatalf("expected 1 loaded, got %d (log: %s)", got, buf.String())
	}
	if !strings.Contains(buf.String(), "duplicate") {
		t.Errorf("expected duplicate error in log, got: %s", buf.String())
	}
}

// logSyncWriter serializes writes so the host's concurrent log.Printf
// calls don't race with the test goroutine reading buf.String().
type logSyncWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w logSyncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
