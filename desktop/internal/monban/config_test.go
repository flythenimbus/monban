package monban

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEncodeDecodeB64RoundTrip(t *testing.T) {
	original := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF}

	encoded := EncodeB64(original)
	decoded, err := DecodeB64(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if string(original) != string(decoded) {
		t.Error("base64 round-trip failed")
	}
}

func TestDecodeB64InvalidInput(t *testing.T) {
	_, err := DecodeB64("not!valid!base64!!!")
	if err == nil {
		t.Error("invalid base64 should fail")
	}
}

func TestSaveLoadConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, ".config", "monban")
	configFile := filepath.Join(configDir, "config.json")

	// Override config path for testing
	origConfigDir := ConfigDir
	origConfigPath := ConfigPath
	ConfigDir = func() string { return configDir }
	ConfigPath = func() string { return configFile }
	defer func() {
		ConfigDir = origConfigDir
		ConfigPath = origConfigPath
	}()

	cfg := &Config{
		Vaults: []VaultEntry{
			{Label: "Documents", Path: "/home/test/Documents"},
		},
		Settings: Settings{
			OpenOnStartup: true,
		},
	}

	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}

	if len(loaded.Vaults) != 1 {
		t.Fatalf("expected 1 vault, got %d", len(loaded.Vaults))
	}
	if loaded.Vaults[0].Path != "/home/test/Documents" {
		t.Errorf("vault path: got %q, want %q", loaded.Vaults[0].Path, "/home/test/Documents")
	}
	if loaded.Settings.OpenOnStartup != true {
		t.Error("OpenOnStartup should be true")
	}
}

func TestLoadConfigBadPermissions(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, ".config", "monban")
	configFile := filepath.Join(configDir, "config.json")

	origConfigDir := ConfigDir
	origConfigPath := ConfigPath
	ConfigDir = func() string { return configDir }
	ConfigPath = func() string { return configFile }
	defer func() {
		ConfigDir = origConfigDir
		ConfigPath = origConfigPath
	}()

	_ = os.MkdirAll(configDir, 0700)
	_ = os.WriteFile(configFile, []byte(`{}`), 0644) // too open

	_, err := LoadConfig()
	if err == nil {
		t.Error("should fail with 0644 permissions")
	}
}

func TestConfigExistsTrue(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.json")

	origConfigPath := ConfigPath
	ConfigPath = func() string { return configFile }
	defer func() { ConfigPath = origConfigPath }()

	_ = os.WriteFile(configFile, []byte(`{}`), 0600)

	if !ConfigExists() {
		t.Error("ConfigExists should return true")
	}
}

func TestConfigExistsFalse(t *testing.T) {
	dir := t.TempDir()

	origConfigPath := ConfigPath
	ConfigPath = func() string { return filepath.Join(dir, "nonexistent.json") }
	defer func() { ConfigPath = origConfigPath }()

	if ConfigExists() {
		t.Error("ConfigExists should return false")
	}
}

func TestVaultEntryIsFile(t *testing.T) {
	folder := VaultEntry{Label: "Docs", Path: "/tmp/docs"}
	if folder.IsFile() {
		t.Error("default vault entry should not be a file")
	}

	folderExplicit := VaultEntry{Label: "Docs", Path: "/tmp/docs", Type: "folder"}
	if folderExplicit.IsFile() {
		t.Error("explicit folder type should not be a file")
	}

	file := VaultEntry{Label: "secret.txt", Path: "/tmp/secret.txt", Type: "file"}
	if !file.IsFile() {
		t.Error("file type vault entry should be a file")
	}
}

func TestSaveLoadConfigWithFileVault(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, ".config", "monban")
	configFile := filepath.Join(configDir, "config.json")

	origConfigDir := ConfigDir
	origConfigPath := ConfigPath
	ConfigDir = func() string { return configDir }
	ConfigPath = func() string { return configFile }
	defer func() {
		ConfigDir = origConfigDir
		ConfigPath = origConfigPath
	}()

	cfg := &Config{
		Vaults: []VaultEntry{
			{Label: "Documents", Path: "/home/test/Documents"},
			{Label: "secret.txt", Path: "/home/test/secret.txt", Type: "file"},
		},
	}

	if err := SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}

	if len(loaded.Vaults) != 2 {
		t.Fatalf("expected 2 vaults, got %d", len(loaded.Vaults))
	}
	if loaded.Vaults[0].IsFile() {
		t.Error("first vault should be a folder")
	}
	if !loaded.Vaults[1].IsFile() {
		t.Error("second vault should be a file")
	}
	if loaded.Vaults[1].Type != "file" {
		t.Errorf("file vault type: got %q, want %q", loaded.Vaults[1].Type, "file")
	}
}

func TestSecureConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	secureFile := filepath.Join(dir, "credentials.json")

	sc := &SecureConfig{
		RpID:     "monban.local",
		HmacSalt: EncodeB64([]byte("test-salt-32-bytes-long-enough!!")),
		Credentials: []CredentialEntry{
			{
				Label:        "Test Key",
				CredentialID: EncodeB64([]byte("cred-id")),
				PublicKeyX:   EncodeB64([]byte("pub-x")),
				PublicKeyY:   EncodeB64([]byte("pub-y")),
				WrappedKey:   EncodeB64([]byte("wrapped")),
			},
		},
	}

	// Write directly (tests don't need root escalation)
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secureFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSecureConfigFrom(secureFile)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.RpID != sc.RpID {
		t.Errorf("RpID: got %q, want %q", loaded.RpID, sc.RpID)
	}
	if len(loaded.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(loaded.Credentials))
	}
	if loaded.Credentials[0].Label != "Test Key" {
		t.Errorf("credential label: got %q, want %q", loaded.Credentials[0].Label, "Test Key")
	}
}

func TestSecureConfigExistsFalse(t *testing.T) {
	dir := t.TempDir()

	origPath := SecureConfigPath
	SecureConfigPath = func() string { return filepath.Join(dir, "nonexistent.json") }
	defer func() { SecureConfigPath = origPath }()

	if SecureConfigExists() {
		t.Error("SecureConfigExists should return false")
	}
}
