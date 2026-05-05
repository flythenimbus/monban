package monban

// --- Types ---

// MasterSecret is the typed handle for the 64-byte master secret.
// All cryptographic uses of the secret go through methods on this type;
// the raw bytes are package-private so callers can't accidentally pass
// the secret where a different key is expected, mix it up with the
// derived encKey, or forget to zeroise it on cleanup.
//
// A *MasterSecret may be nil — Zero() handles that, other methods will
// panic (which is the right behaviour: a nil secret reaching Sign or
// Derive is a programmer error worth surfacing immediately).
type MasterSecret struct {
	bytes []byte
}

// --- Public functions ---

// WrapMasterSecret takes ownership of an existing 64-byte secret. The
// caller must not retain or mutate the slice afterwards — the wrapper
// will zero it on Zero(). Used internally to lift returned bytes from
// the unwrap path into a typed handle.
func WrapMasterSecret(b []byte) *MasterSecret {
	return &MasterSecret{bytes: b}
}

// --- Public methods ---

// Zero overwrites the underlying secret bytes with zeros and clears
// the internal pointer. Safe to call on a nil receiver.
func (m *MasterSecret) Zero() {
	if m == nil {
		return
	}
	ZeroBytes(m.bytes)
	m.bytes = nil
}

// SignConfig sets sc.ConfigHMAC to HMAC-SHA256 of the canonical
// representation of sc, using the configAuthKey derived from this
// secret + hmacSalt. Wraps the package-level SignSecureConfig.
func (m *MasterSecret) SignConfig(sc *SecureConfig, hmacSalt []byte) error {
	return SignSecureConfig(sc, m.bytes, hmacSalt)
}

// VerifyConfig recomputes the HMAC for sc and compares it against
// sc.ConfigHMAC. Returns ErrConfigUnsigned if no HMAC is present,
// ErrConfigTampered on mismatch, nil on success.
func (m *MasterSecret) VerifyConfig(sc *SecureConfig, hmacSalt []byte) error {
	return VerifySecureConfig(sc, m.bytes, hmacSalt)
}

// FileEncKey derives the AES-256 file-encryption key. The caller owns
// the returned bytes and is responsible for zeroing them.
func (m *MasterSecret) FileEncKey(hmacSalt []byte) ([]byte, error) {
	return DeriveEncryptionKey(m.bytes, hmacSalt)
}

// LazyStrictKey derives a per-vault file-encryption key for
// lazy_strict mode. The caller owns the returned bytes and is
// responsible for zeroing them.
func (m *MasterSecret) LazyStrictKey(hmacSalt []byte, vaultPath string) ([]byte, error) {
	return DeriveLazyStrictKey(m.bytes, hmacSalt, vaultPath)
}

// Wrap encrypts the master secret with wrappingKey using AES-256-GCM
// for storage in a CredentialEntry. Used during credential
// registration.
func (m *MasterSecret) Wrap(wrappingKey []byte) ([]byte, error) {
	return WrapKey(wrappingKey, m.bytes)
}
