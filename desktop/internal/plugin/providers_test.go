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
	"testing"
	"time"
)

// authgatemock is a tiny plugin that handles provide:auth_gate by
// reading a mock_config.json sitting in its own plugin dir (cmd.Dir).
// Env vars can't be used: sanitizedEnv strips everything except
// PATH/HOME/TMPDIR before exec, so test-time env would never reach
// the subprocess.
const authGateMockSrc = `package main

import (
	"bufio"
	"encoding/json"
	"os"
	"time"
)

type msg struct {
	ID     string          ` + "`json:\"id,omitempty\"`" + `
	Type   string          ` + "`json:\"type\"`" + `
	Method string          ` + "`json:\"method,omitempty\"`" + `
	Params json.RawMessage ` + "`json:\"params,omitempty\"`" + `
	Result json.RawMessage ` + "`json:\"result,omitempty\"`" + `
}

type cfg struct {
	Name        string ` + "`json:\"name\"`" + `
	Decision    string ` + "`json:\"decision\"`" + `
	Reason      string ` + "`json:\"reason\"`" + `
	RawResponse string ` + "`json:\"raw_response\"`" + `
	SleepMS     int    ` + "`json:\"sleep_ms\"`" + `
}

func loadCfg() cfg {
	// Mock config lives in the plugin's own dir (cmd.Dir sets cwd for us).
	b, err := os.ReadFile("mock_config.json")
	if err != nil {
		return cfg{Name: "authgate-mock", Decision: "allow"}
	}
	var c cfg
	_ = json.Unmarshal(b, &c)
	if c.Name == "" { c.Name = "authgate-mock" }
	if c.Decision == "" { c.Decision = "allow" }
	return c
}

func main() {
	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	c := loadCfg()

	for {
		line, err := r.ReadBytes('\n')
		if err != nil { return }
		var in msg
		if err := json.Unmarshal(line, &in); err != nil { continue }
		switch in.Method {
		case "hello":
			res, _ := json.Marshal(map[string]any{
				"name": c.Name, "version": "0.1.0",
				"hooks": []string{}, "provides": []any{},
				"ready": true,
			})
			out, _ := json.Marshal(msg{ID: in.ID, Type: "response", Result: res})
			_, _ = w.Write(append(out, '\n'))
			_ = w.Flush()
		case "provide:auth_gate":
			if c.SleepMS > 0 {
				time.Sleep(time.Duration(c.SleepMS) * time.Millisecond)
			}
			var result json.RawMessage
			if c.RawResponse != "" {
				result = json.RawMessage(c.RawResponse)
			} else {
				result, _ = json.Marshal(map[string]string{
					"decision": c.Decision, "reason": c.Reason,
				})
			}
			out, _ := json.Marshal(msg{ID: in.ID, Type: "response", Result: result})
			_, _ = w.Write(append(out, '\n'))
			_ = w.Flush()
		case "shutdown":
			return
		}
	}
}
`

// authGateMockConfig is what the test injects into each mock's
// plugin dir to control its behaviour.
type authGateMockConfig struct {
	Name        string `json:"name"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason"`
	RawResponse string `json:"raw_response"`
	SleepMS     int    `json:"sleep_ms"`
}

func buildAuthGateMock(t *testing.T, binDir string) string {
	t.Helper()
	srcDir := filepath.Join(t.TempDir(), "authgatemock")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(authGateMockSrc), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module authgatemock\n\ngo 1.21\n"), 0644); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(binDir, "authgate")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = srcDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build authgatemock: %v\n%s", err, out)
	}
	return binPath
}

// installAuthGateMock drops a signed plugin dir. The mock_config.json
// is read by the mock binary at startup and controls its runtime
// behaviour (decision, reason, simulated delay, malformed response).
func installAuthGateMock(
	t *testing.T,
	pluginsDir string,
	priv ed25519.PrivateKey,
	name string,
	priority int,
	timeoutSeconds int,
	mockCfg authGateMockConfig,
) {
	t.Helper()
	pluginDir := filepath.Join(pluginsDir, name)
	if err := os.MkdirAll(filepath.Join(pluginDir, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	buildAuthGateMock(t, filepath.Join(pluginDir, "bin"))
	_ = os.Rename(
		filepath.Join(pluginDir, "bin", "authgate"),
		filepath.Join(pluginDir, "bin", "mock"),
	)

	// Stamp the mock's name into its config so its hello response
	// matches the manifest's declared name (host rejects mismatches).
	mockCfg.Name = name
	cfgBytes, _ := json.Marshal(mockCfg)
	if err := os.WriteFile(filepath.Join(pluginDir, "mock_config.json"), cfgBytes, 0644); err != nil {
		t.Fatal(err)
	}

	plat := CurrentPlatform()
	m := map[string]any{
		"name":       name,
		"version":    "0.1.0",
		"monban_api": HostAPIVersion,
		"platforms":  []string{plat},
		"kind":       []string{"auth_gate"},
		"provides": []map[string]any{{
			"name":            "auth.gate",
			"priority":        priority,
			"timeout_seconds": timeoutSeconds,
		}},
		"binary": map[string]string{plat: "bin/mock"},
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

// newAuthGateHost spins up a Host with N installed auth_gate mocks
// sharing a single env prefix (t.Setenv scope). Returns the host.
func newAuthGateHost(t *testing.T, priv ed25519.PrivateKey, installs ...func(dir string)) *Host {
	t.Helper()
	pluginsDir := t.TempDir()
	for _, install := range installs {
		install(pluginsDir)
	}

	h := NewHost(HostConfig{
		PluginsDir:  pluginsDir,
		HostVersion: "0.0.0-test",
		Logger:      log.New(&bytes.Buffer{}, "", 0),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		h.Shutdown(sctx)
	})
	return h
}

func TestRunAuthGateAllAllow(t *testing.T) {
	priv := withTempKey(t)
	allow := authGateMockConfig{Decision: "allow"}

	h := newAuthGateHost(t, priv,
		func(d string) { installAuthGateMock(t, d, priv, "gate-a", 10, 5, allow) },
		func(d string) { installAuthGateMock(t, d, priv, "gate-b", 20, 5, allow) },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := h.RunAuthGate(ctx, AuthGateInput{User: "alice"})
	if result.Decision != "allow" {
		t.Fatalf("expected allow, got %+v", result)
	}
}

func TestRunAuthGateNoProvidersAllows(t *testing.T) {
	priv := withTempKey(t)
	// No mocks installed.
	pluginsDir := t.TempDir()
	h := NewHost(HostConfig{
		PluginsDir:  pluginsDir,
		HostVersion: "0.0.0-test",
		Logger:      log.New(&bytes.Buffer{}, "", 0),
	})
	_ = priv
	result := h.RunAuthGate(context.Background(), AuthGateInput{User: "alice"})
	if result.Decision != "allow" {
		t.Fatalf("no providers should default-allow, got %+v", result)
	}
}

func TestRunAuthGateDenyShortCircuits(t *testing.T) {
	priv := withTempKey(t)
	deny := authGateMockConfig{Decision: "deny", Reason: "idp_mfa_failed"}
	allow := authGateMockConfig{Decision: "allow"}

	h := newAuthGateHost(t, priv,
		func(d string) { installAuthGateMock(t, d, priv, "gate-a", 10, 5, deny) },
		func(d string) { installAuthGateMock(t, d, priv, "gate-b", 20, 5, allow) },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := h.RunAuthGate(ctx, AuthGateInput{User: "alice"})
	if result.Decision != "deny" {
		t.Fatalf("expected deny, got %+v", result)
	}
	if result.Plugin != "gate-a" {
		t.Errorf("first deny should come from gate-a (priority 10), got plugin=%q", result.Plugin)
	}
	if result.Reason != "idp_mfa_failed" {
		t.Errorf("expected reason idp_mfa_failed, got %q", result.Reason)
	}
}

// A plugin that returns valid JSON with an unknown "decision" value
// (not "allow") must still be treated as deny. This is the
// fail-closed path for broken plugins whose crypto or logic lands
// them outside the protocol.
func TestRunAuthGateUnknownDecisionDeniesFailClosed(t *testing.T) {
	priv := withTempKey(t)
	weird := authGateMockConfig{RawResponse: `{"decision":"maybe","reason":"confused"}`}

	h := newAuthGateHost(t, priv,
		func(d string) { installAuthGateMock(t, d, priv, "gate-weird", 10, 5, weird) },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := h.RunAuthGate(ctx, AuthGateInput{User: "alice"})
	if result.Decision != "deny" {
		t.Fatalf("unknown decision must fail-closed to deny, got %+v", result)
	}
	if result.Plugin != "gate-weird" {
		t.Errorf("expected plugin=gate-weird, got %q", result.Plugin)
	}
}

// A plugin that crashes mid-request (emits no reply frame) must also
// fail-closed to deny, so a buggy plugin can't silently let an
// unlock through.
func TestRunAuthGateCrashedPluginDeniesFailClosed(t *testing.T) {
	priv := withTempKey(t)
	// RawResponse containing non-JSON bytes makes the mock's own
	// json.Marshal fail, so it writes nothing and the subprocess
	// terminates without responding.
	broken := authGateMockConfig{RawResponse: `not valid json at all`}

	h := newAuthGateHost(t, priv,
		func(d string) { installAuthGateMock(t, d, priv, "gate-broken", 10, 5, broken) },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := h.RunAuthGate(ctx, AuthGateInput{User: "alice"})
	if result.Decision != "deny" {
		t.Fatalf("crashed plugin must fail-closed to deny, got %+v", result)
	}
	if result.Plugin != "gate-broken" {
		t.Errorf("expected plugin=gate-broken, got %q", result.Plugin)
	}
}

func TestRunAuthGateTimeoutDenies(t *testing.T) {
	priv := withTempKey(t)
	slow := authGateMockConfig{Decision: "allow", SleepMS: 2000}
	// Install with timeout_seconds=1 so the plugin's response never
	// arrives in time.

	h := newAuthGateHost(t, priv,
		func(d string) { installAuthGateMock(t, d, priv, "gate-slow", 10, 1, slow) },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	result := h.RunAuthGate(ctx, AuthGateInput{User: "alice"})
	elapsed := time.Since(start)
	if result.Decision != "deny" {
		t.Fatalf("timeout must deny (fail-closed), got %+v", result)
	}
	if elapsed > 3*time.Second {
		t.Errorf("timeout respected late: took %s (expected ~1s)", elapsed)
	}
}

func TestRunAuthGatePriorityOrdering(t *testing.T) {
	// Set the priority-5 plugin to deny with a unique reason; the
	// 10/20 plugins allow. The priority-5 deny must be what we see.
	priv := withTempKey(t)
	allow := authGateMockConfig{Decision: "allow"}
	denyFirst := authGateMockConfig{Decision: "deny", Reason: "priority-5-ran-first"}

	h := newAuthGateHost(t, priv,
		func(d string) { installAuthGateMock(t, d, priv, "gate-a", 10, 5, allow) },
		func(d string) { installAuthGateMock(t, d, priv, "gate-b", 20, 5, allow) },
		func(d string) { installAuthGateMock(t, d, priv, "gate-c", 5, 5, denyFirst) },
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := h.RunAuthGate(ctx, AuthGateInput{User: "alice"})
	if result.Decision != "deny" {
		t.Fatalf("expected deny, got %+v", result)
	}
	if result.Plugin != "gate-c" {
		t.Errorf("priority 5 (gate-c) should fire first; got plugin=%q", result.Plugin)
	}
	if result.Reason != "priority-5-ran-first" {
		t.Errorf("wrong plugin's reason surfaced; got %q", result.Reason)
	}
}
