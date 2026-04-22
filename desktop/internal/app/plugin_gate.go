package app

import (
	"fmt"
	"os"
)

// allowDisablePluginsPath is the sentinel file path. Presence authorises
// the `--disable-plugins` CLI flag. Absence makes the flag a no-op.
// Both require the file to be owned by root (uid 0) so a user-writable
// location can't defeat the gate.
const allowDisablePluginsPath = "/etc/monban/allow_disable_plugins"

// AllowDisablePlugins returns nil if the caller is permitted to disable
// the plugin host via the `--disable-plugins` CLI flag. Implementation
// of C1's enterprise-safe escape hatch:
//
//   - Personal users: `sudo mkdir -p /etc/monban && sudo touch
//     /etc/monban/allow_disable_plugins` once, then the flag works.
//   - Enterprise: MDM/managed prefs never provisions the file, so
//     the flag is a no-op — an attacker with the YubiKey + PIN
//     cannot bypass a corporate auth_gate by starting Monban with
//     `--disable-plugins`.
//
// The file must be owned by root. A same-uid attacker cannot create
// root-owned files at protected paths, so this is safe to rely on.
func AllowDisablePlugins() error {
	st, err := os.Stat(allowDisablePluginsPath)
	if err != nil {
		return fmt.Errorf("sentinel not present at %s (sudo touch it to enable)", allowDisablePluginsPath)
	}
	uid, ok := statUID(st)
	if !ok {
		return fmt.Errorf("cannot read sentinel owner")
	}
	if uid != 0 {
		return fmt.Errorf("sentinel %s not owned by root (uid %d)", allowDisablePluginsPath, uid)
	}
	return nil
}
