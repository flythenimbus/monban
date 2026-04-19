package monban

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DecryptMode string

const (
	DecryptEager      DecryptMode = "eager"
	DecryptLazy       DecryptMode = "lazy"
	DecryptLazyStrict DecryptMode = "lazy_strict"
)

// CredentialEntry holds a registered security key's FIDO2 credential and wrapped master secret.
type CredentialEntry struct {
	Label        string `json:"label"`
	CredentialID string `json:"credential_id"` // base64url
	PublicKeyX   string `json:"public_key_x"`  // base64url
	PublicKeyY   string `json:"public_key_y"`  // base64url
	WrappedKey   string `json:"wrapped_key"`   // base64url: nonce || AES-GCM(wrappingKey, masterSecret)
}

// SecureConfig is the HMAC-signed config containing cryptographic material,
// security settings, and the vault list. All fields are protected by a
// FIDO2-derived HMAC — tampering is detected on unlock.
type SecureConfig struct {
	RpID                string                 `json:"rp_id"`
	HmacSalt            string                 `json:"hmac_salt"` // base64url, 32 bytes, immutable after init
	Credentials         []CredentialEntry      `json:"credentials"`
	ForceAuthentication bool                   `json:"force_authentication"`
	VaultDecryptModes   map[string]DecryptMode `json:"vault_decrypt_modes,omitempty"`
	ConfigHMAC          string                 `json:"config_hmac,omitempty"` // base64url HMAC-SHA256 over protected fields
	ConfigCounter       uint64                 `json:"config_counter"`       // monotonic counter, incremented on every signed write
	Vaults              []VaultEntry           `json:"vaults"`
	OpenOnStartup       bool                   `json:"open_on_startup"`
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

// --- Config directory (user-owned, ~/.config/monban/) ---

// ConfigDir is a variable so tests can override it.
var ConfigDir = func() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "monban")
}

// SecureConfigDir and SecureConfigPath are variables so tests can override them.
var SecureConfigDir = func() string {
	return ConfigDir()
}

var SecureConfigPath = func() string {
	return filepath.Join(SecureConfigDir(), "credentials.json")
}

var ErrConfigRollback = fmt.Errorf("secure config counter is behind the encrypted counter — possible rollback attack")

var (
	ErrConfigTampered = fmt.Errorf("secure config HMAC verification failed: config may have been tampered with")
	ErrConfigUnsigned = fmt.Errorf("secure config has no HMAC signature (will be signed on next save)")
)

// --- Public functions ---

func LoadSecureConfig() (*SecureConfig, error) {
	return LoadSecureConfigFrom(SecureConfigPath())
}

// LoadSecureConfigFrom loads the secure config from an arbitrary path.
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

// SaveSecureConfig writes the secure config directly. The config is protected
// by HMAC (FIDO2-derived), not filesystem permissions. Temporarily unlocks the
// config directory for writing if it is locked.
func SaveSecureConfig(sc *SecureConfig) error {
	dir := SecureConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	data, err := MarshalSecureConfig(sc)
	if err != nil {
		return err
	}

	// Temporarily allow writes if directory is locked
	unlocked := unlockConfigDir()

	path := SecureConfigPath()
	writeErr := os.WriteFile(path, data, 0600)

	if unlocked {
		LockConfigDir()
	}

	if writeErr != nil {
		return fmt.Errorf("writing secure config: %w", writeErr)
	}
	return nil
}

// LockConfigDir removes write permission on the config directory, preventing
// file creation or deletion by any user-level process. Call while the app is
// unlocked to protect counter.enc and credentials.json from tampering.
func LockConfigDir() {
	_ = os.Chmod(SecureConfigDir(), 0500)
}

// UnlockConfigDir restores write permission on the config directory.
// Call before locking the app or when the app shuts down.
func UnlockConfigDir() {
	_ = os.Chmod(SecureConfigDir(), 0700)
}

// SaveCounter encrypts the counter value and writes it to counter.enc.
// Uses the file encryption key (derived from master secret via FIDO2).
func SaveCounter(encKey []byte, counter uint64) error {
	plaintext := make([]byte, 8)
	binary.BigEndian.PutUint64(plaintext, counter)

	gcm, err := newGCM(encKey)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating counter nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Write nonce || ciphertext+tag
	out := make([]byte, len(nonce)+len(ciphertext))
	copy(out, nonce)
	copy(out[len(nonce):], ciphertext)

	unlocked := unlockConfigDir()
	writeErr := os.WriteFile(counterPath(), out, 0600)
	if unlocked {
		LockConfigDir()
	}
	if writeErr != nil {
		return fmt.Errorf("writing counter: %w", writeErr)
	}
	return nil
}

// LoadCounter decrypts counter.enc and returns the stored counter value.
// Returns 0 if the file doesn't exist (first run).
func LoadCounter(encKey []byte) (uint64, error) {
	data, err := os.ReadFile(counterPath())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("reading counter: %w", err)
	}

	gcm, err := newGCM(encKey)
	if err != nil {
		return 0, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return 0, fmt.Errorf("counter file too short")
	}

	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return 0, fmt.Errorf("decrypting counter (wrong key or corrupted): %w", err)
	}

	if len(plaintext) != 8 {
		return 0, fmt.Errorf("counter data invalid length: %d", len(plaintext))
	}

	return binary.BigEndian.Uint64(plaintext), nil
}

// CounterFileExists returns true if counter.enc is present on disk.
func CounterFileExists() bool {
	_, err := os.Stat(counterPath())
	return err == nil
}

// VaultDecryptMode returns the current decrypt mode. If empty, returns `"eager"`.
func (sc *SecureConfig) VaultDecryptMode(path string) DecryptMode {
	if m, ok := sc.VaultDecryptModes[path]; ok {
		return m
	}
	return DecryptEager
}

func SecureConfigExists() bool {
	_, err := os.Stat(SecureConfigPath())
	return err == nil
}

// SignSecureConfig computes the HMAC-SHA256 over the protected fields and stores
// it in the ConfigHMAC field. Requires the master secret (FIDO2 must be unlocked).
func SignSecureConfig(sc *SecureConfig, masterSecret, hmacSalt []byte) error {
	authKey, err := DeriveConfigAuthKey(masterSecret, hmacSalt)
	if err != nil {
		return err
	}
	defer ZeroBytes(authKey)

	payload := configHMACPayload(sc)
	mac := hmac.New(sha256.New, authKey)
	mac.Write([]byte(payload))
	sc.ConfigHMAC = EncodeB64(mac.Sum(nil))
	return nil
}

// VerifySecureConfig checks whether the config HMAC is valid. Returns nil if
// the HMAC matches, ErrConfigTampered if it doesn't, or ErrConfigUnsigned if
// no HMAC is present (first launch after upgrade).
func VerifySecureConfig(sc *SecureConfig, masterSecret, hmacSalt []byte) error {
	if sc.ConfigHMAC == "" {
		return ErrConfigUnsigned
	}

	authKey, err := DeriveConfigAuthKey(masterSecret, hmacSalt)
	if err != nil {
		return err
	}
	defer ZeroBytes(authKey)

	stored, err := DecodeB64(sc.ConfigHMAC)
	if err != nil {
		return ErrConfigTampered
	}

	payload := configHMACPayload(sc)
	mac := hmac.New(sha256.New, authKey)
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)

	if !hmac.Equal(stored, expected) {
		return ErrConfigTampered
	}
	return nil
}

// --- Helpers ---

func DecodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func EncodeB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- Private functions ---

// unlockConfigDir temporarily restores write permission if the directory is
// currently locked. Returns true if it was locked (caller should re-lock).
func unlockConfigDir() bool {
	info, err := os.Stat(SecureConfigDir())
	if err != nil {
		return false
	}
	if info.Mode().Perm()&0200 == 0 {
		_ = os.Chmod(SecureConfigDir(), 0700)
		return true
	}
	return false
}

// counterPath returns the path to the encrypted counter file.
func counterPath() string {
	return filepath.Join(SecureConfigDir(), "counter.enc")
}

// --- Config HMAC (tamper detection) ---

// configHMACPayload builds a canonical string from the protected fields of the
// secure config. The output is deterministic regardless of JSON serialisation order.
func configHMACPayload(sc *SecureConfig) string {
	var b strings.Builder

	// Identity fields (immutable but must not be swapped)
	fmt.Fprintf(&b, "rp_id:%s\n", sc.RpID)
	fmt.Fprintf(&b, "hmac_salt:%s\n", sc.HmacSalt)

	// Credentials: sorted by credential_id for determinism
	creds := make([]CredentialEntry, len(sc.Credentials))
	copy(creds, sc.Credentials)
	sort.Slice(creds, func(i, j int) bool {
		return creds[i].CredentialID < creds[j].CredentialID
	})
	for _, c := range creds {
		fmt.Fprintf(&b, "cred:%s:%s:%s:%s:%s\n", c.Label, c.CredentialID, c.PublicKeyX, c.PublicKeyY, c.WrappedKey)
	}

	// Policy fields
	fmt.Fprintf(&b, "force_authentication:%v\n", sc.ForceAuthentication)

	// Vault decrypt modes: sorted by path
	if len(sc.VaultDecryptModes) > 0 {
		paths := make([]string, 0, len(sc.VaultDecryptModes))
		for p := range sc.VaultDecryptModes {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			fmt.Fprintf(&b, "vault_mode:%s:%s\n", p, sc.VaultDecryptModes[p])
		}
	}

	// Vaults: sorted by path for determinism
	vaults := make([]VaultEntry, len(sc.Vaults))
	copy(vaults, sc.Vaults)
	sort.Slice(vaults, func(i, j int) bool { return vaults[i].Path < vaults[j].Path })
	for _, v := range vaults {
		fmt.Fprintf(&b, "vault:%s:%s:%s\n", v.Label, v.Path, v.Type)
	}

	fmt.Fprintf(&b, "open_on_startup:%v\n", sc.OpenOnStartup)
	fmt.Fprintf(&b, "config_counter:%d\n", sc.ConfigCounter)

	return b.String()
}
