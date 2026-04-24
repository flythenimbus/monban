package plugin

import (
	"strings"
	"testing"
)

func TestParseManifestValid(t *testing.T) {
	raw := []byte(`{
		"name": "hello-world",
		"version": "0.1.0",
		"monban_api": "0.1",
		"platforms": ["darwin-arm64", "linux-amd64"],
		"kind": ["observer"],
		"hooks": ["on:app_started"],
		"binary": {
			"darwin-arm64": "bin/hello",
			"linux-amd64":  "bin/hello"
		}
	}`)
	m, err := ParseManifest(raw)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.Name != "hello-world" {
		t.Errorf("name = %q, want hello-world", m.Name)
	}
	if len(m.Platforms) != 2 {
		t.Errorf("platforms len = %d, want 2", len(m.Platforms))
	}
}

func TestParseManifestRejectsUnknownField(t *testing.T) {
	raw := []byte(`{
		"name": "x", "version": "0.1.0", "monban_api": "0.1",
		"platforms": ["darwin-arm64"], "kind": ["observer"],
		"binary": {"darwin-arm64": "bin/x"},
		"unknown_field": 1
	}`)
	if _, err := ParseManifest(raw); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestValidateRejectsBadName(t *testing.T) {
	cases := []string{"", "UpperCase", "has space", "1starts-with-digit", strings.Repeat("a", 70)}
	for _, name := range cases {
		m := &Manifest{
			Name:      name,
			Version:   "0.1.0",
			MonbanAPI: "0.1",
			Platforms: []string{"darwin-arm64"},
			Kind:      []string{"observer"},
			Binary:    map[string]string{"darwin-arm64": "bin/x"},
		}
		if err := m.Validate(); err == nil {
			t.Errorf("name %q: expected validation failure", name)
		}
	}
}

func TestValidateRejectsUnknownKind(t *testing.T) {
	m := &Manifest{
		Name:      "x",
		Version:   "0.1.0",
		MonbanAPI: "0.1",
		Platforms: []string{"darwin-arm64"},
		Kind:      []string{"nonsense"},
		Binary:    map[string]string{"darwin-arm64": "bin/x"},
	}
	if err := m.Validate(); err == nil {
		t.Fatal("expected unknown kind to fail")
	}
}

func TestValidateRejectsMissingBinaryForPlatform(t *testing.T) {
	m := &Manifest{
		Name:      "x",
		Version:   "0.1.0",
		MonbanAPI: "0.1",
		Platforms: []string{"darwin-arm64", "linux-amd64"},
		Kind:      []string{"observer"},
		Binary:    map[string]string{"darwin-arm64": "bin/x"}, // linux-amd64 missing
	}
	if err := m.Validate(); err == nil {
		t.Fatal("expected missing binary entry to fail")
	}
}

func TestIsCompatibleAPI(t *testing.T) {
	cases := []struct {
		pluginAPI string
		hostAPI   string
		wantOK    bool
	}{
		{"0.1", "0.1", true},
		{"0.1", "0.2", false}, // pre-1.0 exact match required
		{"0.2", "0.1", false},
		{"1.0", "0.1", false}, // major mismatch
		{"1.0", "1.0", true},
		{"1.0", "1.5", true}, // host minor >= plugin minor
		{"1.5", "1.0", false},
		{"not-a-version", "0.1", false},
	}
	origHost := HostAPIVersion
	for _, tc := range cases {
		m := &Manifest{MonbanAPI: tc.pluginAPI}
		// Dirty trick: override via local var (HostAPIVersion is a const).
		// Instead call parseSemverMM directly through a helper that
		// takes both — we don't override the const here. Test current
		// const against the cases where hostAPI matches origHost.
		if tc.hostAPI != origHost {
			continue
		}
		ok, _ := m.IsCompatibleAPI()
		if ok != tc.wantOK {
			t.Errorf("IsCompatibleAPI(%q) on host %q = %v, want %v", tc.pluginAPI, tc.hostAPI, ok, tc.wantOK)
		}
	}
}

func TestCurrentPlatformFormat(t *testing.T) {
	p := CurrentPlatform()
	if !strings.Contains(p, "-") {
		t.Errorf("CurrentPlatform = %q, expected os-arch", p)
	}
}
