package plugin

// defaultDevPubKeyHex is the hex-encoded ed25519 public key for the
// committed dev release key. The matching private key lives at
// cmd/monban-sign/testkeys/dev-release.key (git-ignored in production
// builds but committed for local iteration).
//
// Production release builds override ReleasePubKeyHex via ldflags.
const defaultDevPubKeyHex = "69ffa8c57a2f1bbcc6e95f195094ecfbe55d28e95f7cdf7ae4ae751dbc9dae6d"
