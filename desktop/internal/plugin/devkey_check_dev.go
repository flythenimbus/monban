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
