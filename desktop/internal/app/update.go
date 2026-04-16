package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type UpdateInfo struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseURL      string `json:"release_url"`
}

func (a *App) GetVersion() string {
	return Version
}

func (a *App) CheckForUpdate() (UpdateInfo, error) {
	info := UpdateInfo{CurrentVersion: Version}

	if Version == "dev" {
		info.CurrentVersion = "0.0.1"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/flythenimbus/monban/releases/latest")
	if err != nil {
		return info, fmt.Errorf("checking for updates: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return info, fmt.Errorf("parsing release response: %w", err)
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	info.LatestVersion = latest
	info.ReleaseURL = release.HTMLURL
	info.UpdateAvailable = compareSemver(info.CurrentVersion, latest) < 0

	return info, nil
}

// compareSemver returns -1, 0, or 1.
func compareSemver(current, latest string) int {
	var cMaj, cMin, cPat, lMaj, lMin, lPat int
	_, _ = fmt.Sscanf(current, "%d.%d.%d", &cMaj, &cMin, &cPat)
	_, _ = fmt.Sscanf(latest, "%d.%d.%d", &lMaj, &lMin, &lPat)

	switch {
	case cMaj != lMaj:
		if cMaj < lMaj {
			return -1
		}
		return 1
	case cMin != lMin:
		if cMin < lMin {
			return -1
		}
		return 1
	case cPat != lPat:
		if cPat < lPat {
			return -1
		}
		return 1
	default:
		return 0
	}
}
