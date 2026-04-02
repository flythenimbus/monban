package monban

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CredentialEntry holds a registered YubiKey's FIDO2 credential and wrapped master secret.
type CredentialEntry struct {
	Label        string `json:"label"`
	CredentialID string `json:"credential_id"` // base64url
	PublicKeyX   string `json:"public_key_x"`  // base64url
	PublicKeyY   string `json:"public_key_y"`  // base64url
	WrappedKey   string `json:"wrapped_key"`   // base64url: nonce || AES-GCM(wrappingKey, masterSecret)
}

// SecureConfig is the root-owned config containing cryptographic material
// and security-sensitive settings. Writable only by root.
type SecureConfig struct {
	RpID                string            `json:"rp_id"`
	HmacSalt            string            `json:"hmac_salt"` // base64url, 32 bytes, immutable after init
	Credentials         []CredentialEntry `json:"credentials"`
	ForceAuthentication bool              `json:"force_authentication"`
	SudoGate            string            `json:"sudo_gate"` // "off" (default), "default" (sufficient), "strict" (required)
}

// VaultEntry describes a protected folder or file.
type VaultEntry struct {
	Label string `json:"label"`
	Path  string `json:"path"`           // the protected folder or file path
	Type  string `json:"type,omitempty"` // "folder" (default) or "file"
}

// IsFile returns true if this vault entry protects a single file.
func (v VaultEntry) IsFile() bool {
	return v.Type == "file"
}

// Settings holds non-sensitive user preferences.
type Settings struct {
	OpenOnStartup bool `json:"open_on_startup"`
}

// Config is the user-owned config containing settings and vault list.
// Stored in the user's home directory.
type Config struct {
	Vaults   []VaultEntry `json:"vaults"`
	Settings Settings     `json:"settings"`
}

// --- User config (user-owned, ~/.config/monban/config.json) ---

// ConfigDir and ConfigPath are variables so tests can override them.
var ConfigDir = func() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "monban")
}

var ConfigPath = func() string {
	return filepath.Join(ConfigDir(), "config.json")
}

func LoadConfig() (*Config, error) {
	return LoadConfigFrom(ConfigPath())
}

// LoadConfigFrom loads user config from an arbitrary path.
func LoadConfigFrom(path string) (*Config, error) {
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

// --- Secure config (root-owned, /Library/Application Support/monban/ or /etc/monban/) ---

// SecureConfigDir returns the platform-specific system directory for the secure config.
var SecureConfigDir = func() string {
	return secureConfigDir()
}

var SecureConfigPath = func() string {
	return filepath.Join(SecureConfigDir(), "credentials.json")
}

func LoadSecureConfig() (*SecureConfig, error) {
	return LoadSecureConfigFrom(SecureConfigPath())
}

// LoadSecureConfigFrom loads the secure config from an arbitrary path.
// The secure config is root-owned but world-readable (0644).
func LoadSecureConfigFrom(path string) (*SecureConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secure config not found: %w", err)
	}

	var sc SecureConfig
	if err := json.Unmarshal(data, &sc); err != nil {
		return nil, fmt.Errorf("parsing secure config: %w", err)
	}

	return &sc, nil
}

// MarshalSecureConfig serializes the secure config to JSON.
func MarshalSecureConfig(sc *SecureConfig) ([]byte, error) {
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling secure config: %w", err)
	}
	return data, nil
}

// SaveSecureConfig writes the secure config via root escalation.
func SaveSecureConfig(sc *SecureConfig) error {
	data, err := MarshalSecureConfig(sc)
	if err != nil {
		return err
	}

	return BatchPrivilegedWrites([]PrivilegedWrite{{
		Path:      SecureConfigPath(),
		Content:   string(data),
		Mode:      0644,
		MkdirPath: SecureConfigDir(),
	}})
}

func SecureConfigExists() bool {
	_, err := os.Stat(SecureConfigPath())
	return err == nil
}

// --- Migration ---

// legacyConfig mirrors the old config.json layout that included credential fields.
type legacyConfig struct {
	RpID        string            `json:"rp_id"`
	HmacSalt    string            `json:"hmac_salt"`
	Credentials []CredentialEntry `json:"credentials"`
	Vaults      []VaultEntry      `json:"vaults"`
	Settings    struct {
		OpenOnStartup       bool `json:"open_on_startup"`
		ForceAuthentication bool `json:"force_authentication"`
	} `json:"settings"`
}

// MigrateConfigIfNeeded checks if config.json contains legacy credential fields
// and migrates them to the secure config (credentials.json). This is a one-time
// migration from the old single-file layout to the split layout.
// Returns true if migration was performed.
func MigrateConfigIfNeeded() (bool, error) {
	if SecureConfigExists() {
		return false, nil
	}

	path := ConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return false, nil // no config at all, nothing to migrate
	}

	var legacy legacyConfig
	if err := json.Unmarshal(data, &legacy); err != nil {
		return false, nil
	}

	// Check if legacy fields are present
	if legacy.HmacSalt == "" || len(legacy.Credentials) == 0 {
		return false, nil
	}

	// Build secure config from legacy fields
	sc := &SecureConfig{
		RpID:                legacy.RpID,
		HmacSalt:            legacy.HmacSalt,
		Credentials:         legacy.Credentials,
		ForceAuthentication: legacy.Settings.ForceAuthentication,
	}

	if err := SaveSecureConfig(sc); err != nil {
		return false, fmt.Errorf("migrating credentials to secure config: %w", err)
	}

	// Rewrite config.json without credential fields
	cfg := &Config{
		Vaults: legacy.Vaults,
		Settings: Settings{
			OpenOnStartup: legacy.Settings.OpenOnStartup,
		},
	}
	if err := SaveConfig(cfg); err != nil {
		return false, fmt.Errorf("rewriting config after migration: %w", err)
	}

	return true, nil
}

// --- Helpers ---

func DecodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func EncodeB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
