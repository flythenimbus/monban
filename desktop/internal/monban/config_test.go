package monban

import (
	"bytes"
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

// --- SecureConfig round-trip tests ---

func TestSecureConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	secureFile := filepath.Join(dir, "credentials.json")

	sc := &SecureConfig{
		RpID:     "monban.local",
		HmacSalt: EncodeB64([]byte("test-salt-32-bytes-long-enough!!")),
		Credentials: []CredentialEntry{
			{Label: "Test Key", CredentialID: EncodeB64([]byte("cred-id")), PublicKeyX: EncodeB64([]byte("pub-x")), PublicKeyY: EncodeB64([]byte("pub-y")), WrappedKey: EncodeB64([]byte("wrapped"))},
		},
		Vaults: []VaultEntry{
			{Label: "Docs", Path: "/home/test/Documents"},
			{Label: "secret.txt", Path: "/home/test/secret.txt", Type: "file"},
		},
		OpenOnStartup: true,
	}

	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secureFile, data, 0600); err != nil {
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
	if len(loaded.Vaults) != 2 {
		t.Fatalf("expected 2 vaults, got %d", len(loaded.Vaults))
	}
	if !loaded.Vaults[1].IsFile() {
		t.Error("second vault should be a file")
	}
	if !loaded.OpenOnStartup {
		t.Error("OpenOnStartup should be true")
	}
}

func TestSaveSecureConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	secureFile := filepath.Join(dir, "credentials.json")

	origDir := SecureConfigDir
	origPath := SecureConfigPath
	SecureConfigDir = func() string { return dir }
	SecureConfigPath = func() string { return secureFile }
	defer func() {
		SecureConfigDir = origDir
		SecureConfigPath = origPath
	}()

	sc := &SecureConfig{
		RpID:                "monban.local",
		HmacSalt:            EncodeB64([]byte("test-salt-32-bytes-long-enough!!")),
		Credentials:         []CredentialEntry{{Label: "Key", CredentialID: "c1", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
		ForceAuthentication: true,
		Vaults:              []VaultEntry{{Label: "Docs", Path: "/test/docs"}},
		OpenOnStartup:       true,
	}

	if err := SaveSecureConfig(sc); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(secureFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("secure config permissions: got %o, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadSecureConfig()
	if err != nil {
		t.Fatal(err)
	}

	if loaded.RpID != sc.RpID {
		t.Errorf("RpID: got %q, want %q", loaded.RpID, sc.RpID)
	}
	if loaded.ForceAuthentication != true {
		t.Error("ForceAuthentication should be true")
	}
	if len(loaded.Vaults) != 1 {
		t.Fatalf("expected 1 vault, got %d", len(loaded.Vaults))
	}
	if !loaded.OpenOnStartup {
		t.Error("OpenOnStartup should be true")
	}
}

func TestSaveSecureConfigCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")

	origDir := SecureConfigDir
	origPath := SecureConfigPath
	SecureConfigDir = func() string { return dir }
	SecureConfigPath = func() string { return filepath.Join(dir, "credentials.json") }
	defer func() {
		SecureConfigDir = origDir
		SecureConfigPath = origPath
	}()

	sc := &SecureConfig{RpID: "monban.local"}
	if err := SaveSecureConfig(sc); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "credentials.json")); err != nil {
		t.Error("SaveSecureConfig should create the directory")
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

func TestSecureConfigDirPointsToConfigDir(t *testing.T) {
	if SecureConfigDir() != ConfigDir() {
		t.Errorf("SecureConfigDir should equal ConfigDir: %q != %q", SecureConfigDir(), ConfigDir())
	}
}

// --- VaultDecryptMode tests ---

func TestVaultDecryptModeDefault(t *testing.T) {
	sc := &SecureConfig{}
	if sc.VaultDecryptMode("/any/path") != DecryptEager {
		t.Error("nil map should default to eager")
	}
}

func TestVaultDecryptModeFromMap(t *testing.T) {
	sc := &SecureConfig{
		VaultDecryptModes: map[string]DecryptMode{
			"/home/user/docs":   DecryptLazy,
			"/home/user/secret": DecryptLazyStrict,
		},
	}

	if sc.VaultDecryptMode("/home/user/docs") != DecryptLazy {
		t.Error("should return lazy for docs")
	}
	if sc.VaultDecryptMode("/home/user/secret") != DecryptLazyStrict {
		t.Error("should return lazy_strict for secret")
	}
	if sc.VaultDecryptMode("/home/user/other") != DecryptEager {
		t.Error("missing path should default to eager")
	}
}

func TestVaultDecryptModesSerialize(t *testing.T) {
	sc := &SecureConfig{
		RpID:     "monban.local",
		HmacSalt: EncodeB64([]byte("test-salt-32-bytes-long-enough!!")),
		Credentials: []CredentialEntry{
			{Label: "Test Key", CredentialID: EncodeB64([]byte("cred-id")), PublicKeyX: EncodeB64([]byte("pub-x")), PublicKeyY: EncodeB64([]byte("pub-y")), WrappedKey: EncodeB64([]byte("wrapped"))},
		},
		VaultDecryptModes: map[string]DecryptMode{"/home/user/docs": DecryptLazy},
	}

	dir := t.TempDir()
	secureFile := filepath.Join(dir, "credentials.json")

	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secureFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSecureConfigFrom(secureFile)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.VaultDecryptMode("/home/user/docs") != DecryptLazy {
		t.Error("loaded mode should be lazy")
	}
	if loaded.VaultDecryptMode("/other") != DecryptEager {
		t.Error("missing path should default to eager after load")
	}
}

func TestVaultDecryptModesOmittedWhenEmpty(t *testing.T) {
	sc := &SecureConfig{
		RpID:     "monban.local",
		HmacSalt: EncodeB64([]byte("test-salt-32-bytes-long-enough!!")),
		Credentials: []CredentialEntry{
			{Label: "Test Key", CredentialID: EncodeB64([]byte("cred-id")), PublicKeyX: EncodeB64([]byte("pub-x")), PublicKeyY: EncodeB64([]byte("pub-y")), WrappedKey: EncodeB64([]byte("wrapped"))},
		},
	}

	data, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	if _, exists := raw["vault_decrypt_modes"]; exists {
		t.Error("vault_decrypt_modes should be omitted when nil")
	}
}

// --- HMAC sign/verify tests ---

func TestSignVerifySecureConfig(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:                "monban.local",
		HmacSalt:            EncodeB64(salt),
		Credentials:         []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
		ForceAuthentication: true,
		Vaults:              []VaultEntry{{Label: "Docs", Path: "/test/docs"}},
		OpenOnStartup:       true,
	}

	if err := SignSecureConfig(sc, master, salt); err != nil {
		t.Fatal(err)
	}
	if sc.ConfigHMAC == "" {
		t.Fatal("ConfigHMAC should be set after signing")
	}

	if err := VerifySecureConfig(sc, master, salt); err != nil {
		t.Fatalf("verification should pass: %v", err)
	}
}

func TestVerifySecureConfigDetectsTampering(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:                "monban.local",
		HmacSalt:            EncodeB64(salt),
		Credentials:         []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
		ForceAuthentication: true,
	}

	_ = SignSecureConfig(sc, master, salt)

	sc.ForceAuthentication = false
	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered, got: %v", err)
	}
}

func TestVerifySecureConfigDetectsCredentialTampering(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:                "monban.local",
		HmacSalt:            EncodeB64(salt),
		Credentials:         []CredentialEntry{{Label: "Key1", CredentialID: "abc", PublicKeyX: "x1", PublicKeyY: "y1", WrappedKey: "w1"}},
		ForceAuthentication: true,
	}

	_ = SignSecureConfig(sc, master, salt)

	sc.Credentials = append(sc.Credentials, CredentialEntry{Label: "Rogue", CredentialID: "rogue", PublicKeyX: "rx", PublicKeyY: "ry", WrappedKey: "rw"})
	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered after adding credential, got: %v", err)
	}
}

func TestVerifySecureConfigUnsigned(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{RpID: "monban.local", HmacSalt: EncodeB64(salt)}

	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigUnsigned {
		t.Fatalf("expected ErrConfigUnsigned, got: %v", err)
	}
}

func TestSignSecureConfigDeterministic(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	make := func() *SecureConfig {
		return &SecureConfig{
			RpID:                "monban.local",
			HmacSalt:            EncodeB64(salt),
			Credentials:         []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
			ForceAuthentication: true,
			Vaults:              []VaultEntry{{Label: "Docs", Path: "/test"}},
		}
	}

	sc1 := make()
	sc2 := make()
	_ = SignSecureConfig(sc1, master, salt)
	_ = SignSecureConfig(sc2, master, salt)

	if sc1.ConfigHMAC != sc2.ConfigHMAC {
		t.Error("same config should produce same HMAC")
	}
}

func TestVerifySecureConfigWrongMasterSecret(t *testing.T) {
	master1 := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	master2 := []byte("DIFFERENT-master-secret-64-bytes-long-enough-for-hkdf-derivatio!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:        "monban.local",
		HmacSalt:    EncodeB64(salt),
		Credentials: []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
	}

	_ = SignSecureConfig(sc, master1, salt)

	if err := VerifySecureConfig(sc, master2, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered with wrong master secret, got: %v", err)
	}
}

func TestSignedSecureConfigSurvivesSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	secureFile := filepath.Join(dir, "credentials.json")

	origDir := SecureConfigDir
	origPath := SecureConfigPath
	SecureConfigDir = func() string { return dir }
	SecureConfigPath = func() string { return secureFile }
	defer func() {
		SecureConfigDir = origDir
		SecureConfigPath = origPath
	}()

	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:                "monban.local",
		HmacSalt:            EncodeB64(salt),
		Credentials:         []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
		ForceAuthentication: true,
		VaultDecryptModes:   map[string]DecryptMode{"/vault": DecryptLazy},
		Vaults:              []VaultEntry{{Label: "Docs", Path: "/test/docs"}},
		OpenOnStartup:       true,
	}

	if err := SignSecureConfig(sc, master, salt); err != nil {
		t.Fatal(err)
	}
	if err := SaveSecureConfig(sc); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSecureConfig()
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifySecureConfig(loaded, master, salt); err != nil {
		t.Fatalf("HMAC should verify after save/load round-trip: %v", err)
	}
}

func TestVerifySecureConfigDetectsVaultModeTampering(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:              "monban.local",
		HmacSalt:          EncodeB64(salt),
		Credentials:       []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
		VaultDecryptModes: map[string]DecryptMode{"/vault": DecryptLazyStrict},
	}

	_ = SignSecureConfig(sc, master, salt)

	sc.VaultDecryptModes["/vault"] = DecryptEager
	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered after vault mode change, got: %v", err)
	}
}

func TestVerifySecureConfigDetectsCredentialRemoval(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:     "monban.local",
		HmacSalt: EncodeB64(salt),
		Credentials: []CredentialEntry{
			{Label: "Key1", CredentialID: "abc", PublicKeyX: "x1", PublicKeyY: "y1", WrappedKey: "w1"},
			{Label: "Key2", CredentialID: "def", PublicKeyX: "x2", PublicKeyY: "y2", WrappedKey: "w2"},
		},
	}

	_ = SignSecureConfig(sc, master, salt)

	sc.Credentials = sc.Credentials[:1]
	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered after credential removal, got: %v", err)
	}
}

func TestVerifySecureConfigDetectsWrappedKeySwap(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:        "monban.local",
		HmacSalt:    EncodeB64(salt),
		Credentials: []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
	}

	_ = SignSecureConfig(sc, master, salt)

	sc.Credentials[0].WrappedKey = "tampered"
	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered after wrapped key swap, got: %v", err)
	}
}

func TestVerifySecureConfigDetectsVaultTampering(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:        "monban.local",
		HmacSalt:    EncodeB64(salt),
		Credentials: []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
		Vaults:      []VaultEntry{{Label: "Docs", Path: "/secret/docs"}, {Label: "Keys", Path: "/secret/keys"}},
	}

	_ = SignSecureConfig(sc, master, salt)

	// Remove a vault entry (attacker wants to stop it from being encrypted)
	sc.Vaults = sc.Vaults[:1]
	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered after vault removal, got: %v", err)
	}
}

func TestVerifySecureConfigDetectsVaultAddition(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:        "monban.local",
		HmacSalt:    EncodeB64(salt),
		Credentials: []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
		Vaults:      []VaultEntry{{Label: "Docs", Path: "/secret/docs"}},
	}

	_ = SignSecureConfig(sc, master, salt)

	sc.Vaults = append(sc.Vaults, VaultEntry{Label: "Rogue", Path: "/rogue"})
	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered after vault addition, got: %v", err)
	}
}

func TestVerifySecureConfigDetectsOpenOnStartupTampering(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:          "monban.local",
		HmacSalt:      EncodeB64(salt),
		Credentials:   []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
		OpenOnStartup: true,
	}

	_ = SignSecureConfig(sc, master, salt)

	sc.OpenOnStartup = false
	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered after OpenOnStartup change, got: %v", err)
	}
}

func TestConfigHMACOmittedWhenEmpty(t *testing.T) {
	sc := &SecureConfig{
		RpID:        "monban.local",
		HmacSalt:    EncodeB64([]byte("test-salt-32-bytes-long-enough!!")),
		Credentials: []CredentialEntry{{Label: "Key", CredentialID: "c", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
	}

	data, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	if _, exists := raw["config_hmac"]; exists {
		t.Error("config_hmac should be omitted when empty")
	}
}

func TestConfigHMACPresentAfterSigning(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:        "monban.local",
		HmacSalt:    EncodeB64(salt),
		Credentials: []CredentialEntry{{Label: "Key", CredentialID: "c", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
	}

	_ = SignSecureConfig(sc, master, salt)

	data, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	if _, exists := raw["config_hmac"]; !exists {
		t.Error("config_hmac should be present after signing")
	}
}

// --- Counter (rollback detection) tests ---

func testEncKey(t *testing.T) []byte {
	t.Helper()
	return bytes.Repeat([]byte{0xAA}, 32)
}

func TestSaveLoadCounterRoundTrip(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() { SecureConfigDir = origDir }()

	key := testEncKey(t)

	if err := SaveCounter(key, 42); err != nil {
		t.Fatal(err)
	}

	val, err := LoadCounter(key)
	if err != nil {
		t.Fatal(err)
	}
	if val != 42 {
		t.Errorf("counter: got %d, want 42", val)
	}
}

func TestLoadCounterMissingFileReturnsZero(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() { SecureConfigDir = origDir }()

	val, err := LoadCounter(testEncKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if val != 0 {
		t.Errorf("missing counter should return 0, got %d", val)
	}
}

func TestLoadCounterWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() { SecureConfigDir = origDir }()

	key1 := bytes.Repeat([]byte{0xAA}, 32)
	key2 := bytes.Repeat([]byte{0xBB}, 32)

	if err := SaveCounter(key1, 10); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCounter(key2)
	if err == nil {
		t.Error("loading counter with wrong key should fail")
	}
}

func TestCounterDetectsRollback(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() { SecureConfigDir = origDir }()

	key := testEncKey(t)

	// Write counter at 5
	if err := SaveCounter(key, 5); err != nil {
		t.Fatal(err)
	}

	storedCounter, _ := LoadCounter(key)

	// Config with counter 3 (rolled back)
	configCounter := uint64(3)
	if configCounter >= storedCounter {
		t.Fatal("test setup wrong: config counter should be less than stored")
	}

	// Config with counter 5 (current) — should pass
	if uint64(5) < storedCounter {
		t.Error("current counter should not be detected as rollback")
	}

	// Config with counter 7 (ahead) — should pass
	if uint64(7) < storedCounter {
		t.Error("future counter should not be detected as rollback")
	}
}

func TestCounterIncrementsAreMonotonic(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() { SecureConfigDir = origDir }()

	key := testEncKey(t)

	for i := uint64(1); i <= 5; i++ {
		if err := SaveCounter(key, i); err != nil {
			t.Fatal(err)
		}
		val, err := LoadCounter(key)
		if err != nil {
			t.Fatal(err)
		}
		if val != i {
			t.Errorf("iteration %d: got %d", i, val)
		}
	}
}

func TestVerifySecureConfigDetectsCounterTampering(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:          "monban.local",
		HmacSalt:      EncodeB64(salt),
		Credentials:   []CredentialEntry{{Label: "Key", CredentialID: "abc", PublicKeyX: "x", PublicKeyY: "y", WrappedKey: "w"}},
		ConfigCounter: 5,
	}

	_ = SignSecureConfig(sc, master, salt)

	sc.ConfigCounter = 3
	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered after counter change, got: %v", err)
	}
}

func TestCounterFileExistsTrue(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() { SecureConfigDir = origDir }()

	_ = SaveCounter(testEncKey(t), 1)

	if !CounterFileExists() {
		t.Error("CounterFileExists should return true after save")
	}
}

func TestCounterFileExistsFalse(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() { SecureConfigDir = origDir }()

	if CounterFileExists() {
		t.Error("CounterFileExists should return false when no file")
	}
}

func TestCounterFileExistsFalseAfterDeletion(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() { SecureConfigDir = origDir }()

	_ = SaveCounter(testEncKey(t), 1)
	_ = os.Remove(counterPath())

	if CounterFileExists() {
		t.Error("CounterFileExists should return false after deletion")
	}
}

// --- Config directory locking tests ---

func TestLockConfigDirPreventsFileCreation(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() {
		UnlockConfigDir() // ensure cleanup
		SecureConfigDir = origDir
	}()

	LockConfigDir()

	err := os.WriteFile(filepath.Join(dir, "newfile"), []byte("test"), 0600)
	if err == nil {
		t.Error("should not be able to create files in locked directory")
	}
}

func TestLockConfigDirPreventsFileDeletion(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() {
		UnlockConfigDir()
		SecureConfigDir = origDir
	}()

	// Create a file before locking
	testFile := filepath.Join(dir, "existing")
	_ = os.WriteFile(testFile, []byte("data"), 0600)

	LockConfigDir()

	err := os.Remove(testFile)
	if err == nil {
		t.Error("should not be able to delete files in locked directory")
	}
}

func TestLockConfigDirAllowsReading(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() {
		UnlockConfigDir()
		SecureConfigDir = origDir
	}()

	testFile := filepath.Join(dir, "readable")
	_ = os.WriteFile(testFile, []byte("data"), 0600)

	LockConfigDir()

	_, err := os.ReadFile(testFile)
	if err != nil {
		t.Errorf("should be able to read files in locked directory: %v", err)
	}
}

func TestUnlockConfigDirRestoresWriteAccess(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() { SecureConfigDir = origDir }()

	LockConfigDir()
	UnlockConfigDir()

	err := os.WriteFile(filepath.Join(dir, "newfile"), []byte("test"), 0600)
	if err != nil {
		t.Errorf("should be able to create files after unlock: %v", err)
	}
}

func TestSaveSecureConfigWorksWhileDirLocked(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	origPath := SecureConfigPath
	SecureConfigDir = func() string { return dir }
	SecureConfigPath = func() string { return filepath.Join(dir, "credentials.json") }
	defer func() {
		UnlockConfigDir()
		SecureConfigDir = origDir
		SecureConfigPath = origPath
	}()

	LockConfigDir()

	sc := &SecureConfig{RpID: "monban.local"}
	if err := SaveSecureConfig(sc); err != nil {
		t.Fatalf("SaveSecureConfig should work while dir is locked: %v", err)
	}

	// Dir should be re-locked after save
	err := os.WriteFile(filepath.Join(dir, "probe"), []byte("x"), 0600)
	if err == nil {
		t.Error("directory should be re-locked after SaveSecureConfig")
	}
}

func TestSaveCounterWorksWhileDirLocked(t *testing.T) {
	dir := t.TempDir()
	origDir := SecureConfigDir
	SecureConfigDir = func() string { return dir }
	defer func() {
		UnlockConfigDir()
		SecureConfigDir = origDir
	}()

	LockConfigDir()

	if err := SaveCounter(testEncKey(t), 99); err != nil {
		t.Fatalf("SaveCounter should work while dir is locked: %v", err)
	}

	// Dir should be re-locked after save
	err := os.WriteFile(filepath.Join(dir, "probe"), []byte("x"), 0600)
	if err == nil {
		t.Error("directory should be re-locked after SaveCounter")
	}

	// Counter should be readable
	val, err := LoadCounter(testEncKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if val != 99 {
		t.Errorf("counter: got %d, want 99", val)
	}
}

func TestPluginSettingsCoveredByHMAC(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc := &SecureConfig{
		RpID:     "monban.local",
		HmacSalt: EncodeB64(salt),
		PluginSettings: map[string]json.RawMessage{
			"hello-world": json.RawMessage(`{"verbose":true}`),
		},
	}
	if err := SignSecureConfig(sc, master, salt); err != nil {
		t.Fatal(err)
	}
	if err := VerifySecureConfig(sc, master, salt); err != nil {
		t.Fatalf("Verify on signed config: %v", err)
	}

	// Tamper with plugin settings after signing
	sc.PluginSettings["hello-world"] = json.RawMessage(`{"verbose":false}`)
	if err := VerifySecureConfig(sc, master, salt); err != ErrConfigTampered {
		t.Fatalf("expected ErrConfigTampered after tampering plugin setting, got %v", err)
	}
}

func TestPluginSettingsCanonicalJSON(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	// Same logical value, different key order / whitespace
	sc1 := &SecureConfig{
		RpID:           "monban.local",
		HmacSalt:       EncodeB64(salt),
		PluginSettings: map[string]json.RawMessage{"p": json.RawMessage(`{"a":1,"b":2}`)},
	}
	sc2 := &SecureConfig{
		RpID:           "monban.local",
		HmacSalt:       EncodeB64(salt),
		PluginSettings: map[string]json.RawMessage{"p": json.RawMessage(`{ "b" : 2 , "a" : 1 }`)},
	}
	_ = SignSecureConfig(sc1, master, salt)
	_ = SignSecureConfig(sc2, master, salt)
	if sc1.ConfigHMAC != sc2.ConfigHMAC {
		t.Errorf("equivalent plugin settings produced different HMAC: %s vs %s", sc1.ConfigHMAC, sc2.ConfigHMAC)
	}
}

func TestPluginSettingsOrderIndependent(t *testing.T) {
	master := []byte("test-master-secret-64-bytes-long-enough-for-hkdf-derivation!!!!!")
	salt := []byte("test-salt-32-bytes-long-enough!!")

	sc1 := &SecureConfig{
		RpID:     "monban.local",
		HmacSalt: EncodeB64(salt),
		PluginSettings: map[string]json.RawMessage{
			"alpha": json.RawMessage(`{"x":1}`),
			"beta":  json.RawMessage(`{"y":2}`),
		},
	}
	sc2 := &SecureConfig{
		RpID:     "monban.local",
		HmacSalt: EncodeB64(salt),
		PluginSettings: map[string]json.RawMessage{
			"beta":  json.RawMessage(`{"y":2}`),
			"alpha": json.RawMessage(`{"x":1}`),
		},
	}
	_ = SignSecureConfig(sc1, master, salt)
	_ = SignSecureConfig(sc2, master, salt)
	if sc1.ConfigHMAC != sc2.ConfigHMAC {
		t.Error("plugin settings HMAC must not depend on map iteration order")
	}
}

