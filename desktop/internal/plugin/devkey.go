package plugin

// defaultDevPubKeyHex is the hex-encoded ed25519 public key for the
// committed dev release pubkey. The matching private key lives at
// cmd/monban-sign/testkeys/dev-release.key (git-ignored; each dev
// generates + holds their own). The committed .pub lets local dev
// Monban builds verify locally-signed plugin artefacts.
//
// Production release builds override ReleasePubKeyHex via ldflags;
// devkey_check_prod.go refuses to start a production binary that
// still trusts this dev key.
const defaultDevPubKeyHex = "27b414e6b388b885cabbf8790ca43778889666c5c7958e57a43e282c31d4d8b6"
