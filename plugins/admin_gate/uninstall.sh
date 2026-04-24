#!/bin/sh
# admin-gate safety uninstaller — run this with sudo from a shell if
# the plugin or Monban itself becomes unreachable and sudo stops
# working. Strips the PAM rule and removes installed files.
#
#   sudo bash plugins/admin_gate/uninstall.sh
#
# Safe to run multiple times; no-op if nothing is installed.

set -eu

TAG='# monban sudo gate'
SUDO_LOCAL=/etc/pam.d/sudo_local

echo "removing monban sudo gate line from $SUDO_LOCAL"
if [ -f "$SUDO_LOCAL" ]; then
    grep -v -F -- "$TAG" "$SUDO_LOCAL" > "$SUDO_LOCAL.monban.tmp" || true
    mv "$SUDO_LOCAL.monban.tmp" "$SUDO_LOCAL"
    chmod 0444 "$SUDO_LOCAL"
fi

echo "removing installed files"
# New install locations (post N20 move to /Library/Monban/).
rm -rf /Library/Monban
# Legacy locations, in case upgrading from a build that used /usr/local/.
rm -f /usr/local/bin/monban-pam-helper
rm -f /usr/local/lib/pam/pam_monban.so
rm -rf "/Library/Application Support/Monban/admin-gate-installed"

echo "done"
