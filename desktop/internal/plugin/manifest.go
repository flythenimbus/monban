package plugin

import (
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Manifest describes a plugin's identity, entry points, hooks, and declared
// capabilities. Loaded from manifest.json inside the plugin directory.
type Manifest struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	MonbanAPI    string            `json:"monban_api"`
	Description  string            `json:"description,omitempty"`
	Homepage     string            `json:"homepage,omitempty"`
	Platforms    []string          `json:"platforms"`
	Kind         []string          `json:"kind"`
	Hooks        []string          `json:"hooks,omitempty"`
	Provides     []ProvideSpec     `json:"provides,omitempty"`
	Binary       map[string]string `json:"binary"`
	InstallPkg   string            `json:"install_pkg,omitempty"`
	UninstallPkg string            `json:"uninstall_pkg,omitempty"`
	UIPanel      string            `json:"ui_panel,omitempty"`
	Settings     json.RawMessage   `json:"settings,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
}

// ProvideSpec declares a provider capability offered by the plugin.
type ProvideSpec struct {
	Name           string `json:"name"`
	Priority       int    `json:"priority"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

var validKinds = map[string]bool{
	"system":    true,
	"auth_gate": true,
	"observer":  true,
	"provider":  true,
	"ui":        true,
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)

// ParseManifest decodes and validates raw manifest JSON.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) Validate() error {
	if !nameRe.MatchString(m.Name) {
		return fmt.Errorf("manifest: invalid name %q (must match %s)", m.Name, nameRe)
	}
	if m.Version == "" {
		return fmt.Errorf("manifest: version required")
	}
	if m.MonbanAPI == "" {
		return fmt.Errorf("manifest: monban_api required")
	}
	if len(m.Platforms) == 0 {
		return fmt.Errorf("manifest: at least one platform required")
	}
	if len(m.Kind) == 0 {
		return fmt.Errorf("manifest: at least one kind required")
	}
	for _, k := range m.Kind {
		if !validKinds[k] {
			return fmt.Errorf("manifest: unknown kind %q", k)
		}
	}
	if len(m.Binary) == 0 {
		return fmt.Errorf("manifest: binary map required")
	}
	for _, plat := range m.Platforms {
		if _, ok := m.Binary[plat]; !ok {
			return fmt.Errorf("manifest: platform %q declared but no binary entry", plat)
		}
	}
	for _, p := range m.Provides {
		if p.Name == "" {
			return fmt.Errorf("manifest: provides entry missing name")
		}
	}
	return nil
}

// CurrentPlatform returns the platform key for the running OS+arch,
// e.g. "darwin-arm64".
func CurrentPlatform() string {
	return runtime.GOOS + "-" + runtime.GOARCH
}

// SupportsCurrentPlatform reports whether the manifest can run on this host.
func (m *Manifest) SupportsCurrentPlatform() bool {
	plat := CurrentPlatform()
	for _, p := range m.Platforms {
		if p == plat {
			return true
		}
	}
	return false
}

// BinaryForCurrentPlatform returns the relative path of the plugin binary
// for the running OS+arch, or empty string if unsupported.
func (m *Manifest) BinaryForCurrentPlatform() string {
	return m.Binary[CurrentPlatform()]
}

// IsCompatibleAPI checks a plugin's monban_api against the host's
// HostAPIVersion. Major mismatch or plugin-newer-than-host minor → false.
func (m *Manifest) IsCompatibleAPI() (bool, string) {
	pmaj, pmin, err := parseSemverMM(m.MonbanAPI)
	if err != nil {
		return false, fmt.Sprintf("invalid monban_api %q: %v", m.MonbanAPI, err)
	}
	hmaj, hmin, err := parseSemverMM(HostAPIVersion)
	if err != nil {
		return false, fmt.Sprintf("host api version broken: %v", err)
	}
	if pmaj != hmaj {
		return false, fmt.Sprintf("plugin targets api %d.x, host is %d.x", pmaj, hmaj)
	}
	// Pre-1.0: any minor mismatch is breaking.
	if hmaj == 0 && pmin != hmin {
		return false, fmt.Sprintf("pre-1.0: plugin targets %s, host is %s (exact match required)", m.MonbanAPI, HostAPIVersion)
	}
	if pmin > hmin {
		return false, fmt.Sprintf("plugin needs api %s, host is %s — update Monban", m.MonbanAPI, HostAPIVersion)
	}
	return true, ""
}

func parseSemverMM(s string) (int, int, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("expected <major>.<minor>")
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("major: %w", err)
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("minor: %w", err)
	}
	return maj, min, nil
}
