package plugin

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed catalog.json
var embeddedCatalog []byte

// Catalog is the static list of official plugins known to this build of
// Monban. It ships embedded in the binary — tampering is already covered
// by the binary signature, so no separate signature file is needed.
type Catalog struct {
	Schema  int            `json:"schema"`
	Plugins []CatalogEntry `json:"plugins"`
}

// CatalogEntry describes one installable plugin. URLs may contain
// `{version}` and `{platform}` placeholders, which the installer expands
// at install time based on the running host.
type CatalogEntry struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Description    string   `json:"description,omitempty"`
	Platforms      []string `json:"platforms"`
	ManifestURL    string   `json:"manifest_url"`
	ManifestSigURL string   `json:"manifest_sig_url"`
	TarballURL     string   `json:"tarball_url"`
	TarballSigURL  string   `json:"tarball_sig_url"`
}

// LoadCatalog parses the embedded catalog.
func LoadCatalog() (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(embeddedCatalog, &c); err != nil {
		return nil, fmt.Errorf("decode embedded catalog: %w", err)
	}
	return &c, nil
}

// SupportsPlatform reports whether this entry targets the current OS+arch.
func (e *CatalogEntry) SupportsPlatform(platform string) bool {
	for _, p := range e.Platforms {
		if p == platform {
			return true
		}
	}
	return false
}

// ResolvedURLs returns the four download URLs for the given platform with
// {version} and {platform} placeholders substituted.
func (e *CatalogEntry) ResolvedURLs(platform string) (manifest, manifestSig, tarball, tarballSig string) {
	return e.expand(e.ManifestURL, platform),
		e.expand(e.ManifestSigURL, platform),
		e.expand(e.TarballURL, platform),
		e.expand(e.TarballSigURL, platform)
}

func (e *CatalogEntry) expand(u, platform string) string {
	u = strings.ReplaceAll(u, "{version}", e.Version)
	u = strings.ReplaceAll(u, "{platform}", platform)
	return u
}
