//go:build !production

package plugin

import "log"

// CheckReleaseKeyConfig warns on dev builds if the binary is still
// trusting the committed dev pubkey (normal during local iteration).
// Production builds replace this implementation via the build tag and
// refuse to start in that state — see devkey_check_prod.go.
func CheckReleaseKeyConfig() {
	if ReleasePubKeyHex == defaultDevPubKeyHex {
		log.Println("plugin: dev build using committed dev pubkey for verification (ok for local iteration; do not ship)")
	}
}

// requireBinaryHashPin reports whether manifests must carry a
// binary_sha256 entry for the running platform. Dev builds tolerate
// a missing field so iteration doesn't require running build.sh on
// every code change; production builds enforce it.
func requireBinaryHashPin() bool { return false }
