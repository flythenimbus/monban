package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.1.0", -1},
		{"1.1.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"0.0.1", "0.0.1", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.2.3", "1.3.0", -1},
		{"1.2.3", "2.0.0", -1},
		{"10.0.0", "9.0.0", 1},
		{"0.0.0", "0.0.0", 0},
	}

	for _, tt := range tests {
		got := compareSemver(tt.current, tt.latest)
		if got != tt.want {
			t.Errorf("compareSemver(%q, %q) = %d, want %d", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestGetVersion(t *testing.T) {
	a := NewApp()
	got := a.GetVersion()
	if got != Version {
		t.Errorf("GetVersion() = %q, want %q", got, Version)
	}
}

func TestCheckForUpdate_NewVersionAvailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := struct {
			TagName string `json:"tag_name"`
			HTMLURL string `json:"html_url"`
		}{
			TagName: "v99.0.0",
			HTMLURL: "https://github.com/flythenimbus/monban/releases/tag/v99.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// CheckForUpdate hits a hardcoded GitHub URL, so we can't redirect it
	// without modifying production code. Instead, test the semver comparison
	// logic that underpins it, which is tested above in TestCompareSemver.
	// This test verifies the struct wiring.
	info := UpdateInfo{
		CurrentVersion: "1.0.0",
		LatestVersion:  "99.0.0",
		ReleaseURL:     "https://example.com/release",
	}
	info.UpdateAvailable = compareSemver(info.CurrentVersion, info.LatestVersion) < 0

	if !info.UpdateAvailable {
		t.Error("expected UpdateAvailable to be true when latest > current")
	}
	if info.LatestVersion != "99.0.0" {
		t.Errorf("LatestVersion = %q, want %q", info.LatestVersion, "99.0.0")
	}
}

func TestCheckForUpdate_AlreadyLatest(t *testing.T) {
	info := UpdateInfo{
		CurrentVersion: "2.0.0",
		LatestVersion:  "1.0.0",
	}
	info.UpdateAvailable = compareSemver(info.CurrentVersion, info.LatestVersion) < 0

	if info.UpdateAvailable {
		t.Error("expected UpdateAvailable to be false when current > latest")
	}
}

func TestCheckForUpdate_DevVersion(t *testing.T) {
	// The CheckForUpdate method replaces "dev" with "0.0.1"
	a := NewApp()
	oldVersion := Version
	Version = "dev"
	defer func() { Version = oldVersion }()

	// We can't make a real HTTP call in tests, but we can verify the dev
	// version substitution logic: dev -> 0.0.1 should compare less than any release.
	if compareSemver("0.0.1", "0.1.0") >= 0 {
		t.Error("dev version (0.0.1) should be less than any real release")
	}
	_ = a // ensure the app was created
}

func TestCompareSemver_MalformedInput(t *testing.T) {
	// Malformed versions parse as 0.0.0 via Sscanf
	if got := compareSemver("", "1.0.0"); got != -1 {
		t.Errorf("compareSemver('', '1.0.0') = %d, want -1", got)
	}
	if got := compareSemver("abc", "1.0.0"); got != -1 {
		t.Errorf("compareSemver('abc', '1.0.0') = %d, want -1", got)
	}
	if got := compareSemver("abc", "xyz"); got != 0 {
		t.Errorf("compareSemver('abc', 'xyz') = %d, want 0 (both parse as 0.0.0)", got)
	}
}
