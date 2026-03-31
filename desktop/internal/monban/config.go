package monban

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type CredentialEntry struct {
	Label        string `json:"label"`
	CredentialID string `json:"credential_id"` // base64url
	PublicKeyX   string `json:"public_key_x"`  // base64url
	PublicKeyY   string `json:"public_key_y"`  // base64url
	WrappedKey   string `json:"wrapped_key"`   // base64url: nonce || AES-GCM(wrappingKey, masterSecret)
}

type VaultEntry struct {
	Label string `json:"label"`
	Path  string `json:"path"`             // the protected folder or file path
	Type  string `json:"type,omitempty"`   // "folder" (default) or "file"
}

// IsFile returns true if this vault entry protects a single file.
func (v VaultEntry) IsFile() bool {
	return v.Type == "file"
}

type Settings struct {
	OpenOnStartup       bool `json:"open_on_startup"`
	ForceAuthentication bool `json:"force_authentication"`
}

type Config struct {
	RpID        string            `json:"rp_id"`
	HmacSalt    string            `json:"hmac_salt"` // base64url, 32 bytes, immutable after init
	Credentials []CredentialEntry `json:"credentials"`
	Vaults      []VaultEntry      `json:"vaults"`
	Settings    Settings          `json:"settings"`
}

// ConfigDir and ConfigPath are variables so tests can override them.
var ConfigDir = func() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "monban")
}

var ConfigPath = func() string {
	return filepath.Join(ConfigDir(), "config.json")
}

func LoadConfig() (*Config, error) {
	path := ConfigPath()

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("config not found: %w", err)
	}

	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("config file permissions too open: %s (want 0600)", info.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

func SaveConfig(cfg *Config) error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}

	path := ConfigPath()
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}

func ConfigExists() bool {
	_, err := os.Stat(ConfigPath())
	return err == nil
}

func DecodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func EncodeB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
