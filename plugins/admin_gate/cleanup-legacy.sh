#!/bin/bash
# Completely wipe every trace of Monban's admin-gate from this system:
#   - Restore every authorizationdb right from its .monban-backup (the
#     critical part — without this, System Settings admin dialogs point
#     at a mechanism that may not exist and can hang / deny).
#   - Remove the old SecurityAgent plugin bundle.
#   - Remove /etc/pam.d/sudo_local's monban line (and the whole file if
#     it's now empty).
#   - Remove installed helper / PAM module binaries.
#   - Remove the marker file from the new install.
#
# Run with sudo. Idempotent — safe to run multiple times.
#
#   sudo bash plugins/admin_gate/cleanup-legacy.sh

set -u

if [[ $EUID -ne 0 ]]; then
    echo "must run as root: sudo bash $0" >&2
    exit 1
fi

echo "==> restoring authorizationdb rights from backups..."
backups=(/Library/Security/SecurityAgentPlugins/*.monban-backup)
if [[ ! -e "${backups[0]:-}" ]]; then
    echo "    no .monban-backup files found"
else
    for backup in "${backups[@]}"; do
        right=$(basename "$backup" .monban-backup)
        echo "    restoring $right"
        if ! security authorizationdb write "$right" < "$backup" 2>&1 | grep -q YES; then
            echo "    WARN: security authorizationdb write $right did not return YES"
        fi
        rm -f "$backup"
    done
fi

echo "==> removing old SecurityAgent plugin bundle..."
rm -rf /Library/Security/SecurityAgentPlugins/monban-auth.bundle

echo "==> cleaning /etc/pam.d/sudo_local..."
SUDO_LOCAL=/etc/pam.d/sudo_local
if [[ -f "$SUDO_LOCAL" ]]; then
    # Strip every monban-related line (old and new formats).
    grep -v -E '(monban sudo gate|pam_monban\.so|monban-pam-helper)' "$SUDO_LOCAL" \
        > "$SUDO_LOCAL.monban.tmp" || true
    if [[ -s "$SUDO_LOCAL.monban.tmp" ]]; then
        mv "$SUDO_LOCAL.monban.tmp" "$SUDO_LOCAL"
        chmod 0444 "$SUDO_LOCAL"
        chown root:wheel "$SUDO_LOCAL"
        echo "    kept non-monban lines in $SUDO_LOCAL"
    else
        rm -f "$SUDO_LOCAL.monban.tmp" "$SUDO_LOCAL"
        echo "    removed empty $SUDO_LOCAL"
    fi
fi

echo "==> removing helper + PAM module..."
rm -f /usr/local/bin/monban-pam-helper
rm -f /usr/local/lib/pam/pam_monban.so

echo "==> removing new-install marker..."
rm -rf "/Library/Application Support/Monban/admin-gate-installed"

echo "==> forgetting pkg receipts..."
for pkg in com.monban.pkg com.monban.admin-gate.installer; do
    if pkgutil --pkg-info "$pkg" >/dev/null 2>&1; then
        pkgutil --forget "$pkg"
    fi
done

echo
echo "verifying..."
remaining=0
if ls /Library/Security/SecurityAgentPlugins/*.monban-backup >/dev/null 2>&1; then
    echo "  FAIL: .monban-backup files still present"
    remaining=1
fi
for f in /Library/Security/SecurityAgentPlugins/monban-auth.bundle \
         /usr/local/bin/monban-pam-helper \
         /usr/local/lib/pam/pam_monban.so; do
    if [[ -e "$f" ]]; then
        echo "  FAIL: $f still present"
        remaining=1
    fi
done
if [[ -f "$SUDO_LOCAL" ]]; then
    if grep -qE '(monban|pam_monban)' "$SUDO_LOCAL"; then
        echo "  FAIL: $SUDO_LOCAL still references monban"
        remaining=1
    fi
fi

if [[ $remaining -eq 0 ]]; then
    echo "  OK: system clean"
fi
exit $remaining
