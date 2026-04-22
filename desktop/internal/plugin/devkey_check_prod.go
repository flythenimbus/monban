//go:build production

package plugin

import "log"

// CheckReleaseKeyConfig aborts startup when a production build was
// linked without a MONBAN_RELEASE_PUBKEY ldflag override. Without this
// guard a release build accidentally produced with no override would
// trust the committed dev pubkey, and anyone with access to the
// matching (leaked) dev private key could sign plugins it accepts.
// C4: defense-in-depth against a broken CI pipeline or a local
// `go build -tags production` that forgot the ldflag.
func CheckReleaseKeyConfig() {
	if ReleasePubKeyHex == defaultDevPubKeyHex {
		log.Fatal("plugin: production build was linked without MONBAN_RELEASE_PUBKEY override — refusing to start. Every release must bake a non-dev plugin pubkey via -ldflags \"-X monban/internal/plugin.ReleasePubKeyHex=<hex>\".")
	}
}
