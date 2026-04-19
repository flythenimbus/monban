#!/usr/bin/env bash
# test_install.sh — verify a Monban .pkg install dropped every expected file
# and configured the system-level PAM + authorizationdb gating.
#
# Usage:
#   desktop/scripts/test_install.sh
#
# Exits 0 if every check passes, 1 otherwise. Does not require root.

set -u

RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
DIM=$'\033[2m'
RESET=$'\033[0m'

pass=0
fail=0
warn=0

ok()    { printf "  %s✓%s %s\n"                "$GREEN" "$RESET" "$1"; pass=$((pass + 1)); }
bad()   { printf "  %s✗%s %s%s\n"              "$RED"   "$RESET" "$1" "${2:+ ${DIM}— $2${RESET}}"; fail=$((fail + 1)); }
note()  { printf "  %s!%s %s%s\n"              "$YELLOW" "$RESET" "$1" "${2:+ ${DIM}— $2${RESET}}"; warn=$((warn + 1)); }
hdr()   { printf "\n%s%s%s\n"                  "$DIM" "$1" "$RESET"; }

# --- check functions ------------------------------------------------------

# check_file <path> <expected_owner> <expected_mode_octal> <label>
check_file() {
    local path="$1" owner="$2" mode="$3" label="$4"
    if [[ ! -e "$path" ]]; then
        bad "$label" "missing: $path"
        return
    fi
    local actual_owner actual_mode
    actual_owner=$(stat -f "%Su:%Sg" "$path")
    actual_mode=$(stat -f "%OLp" "$path")
    if [[ "$actual_owner" != "$owner" ]]; then
        bad "$label" "$path owner $actual_owner, want $owner"
        return
    fi
    if [[ -n "$mode" && "$actual_mode" != "$mode" ]]; then
        bad "$label" "$path mode $actual_mode, want $mode"
        return
    fi
    ok "$label"
}

# check_dir <path> <expected_owner> <label>
check_dir() {
    local path="$1" owner="$2" label="$3"
    if [[ ! -d "$path" ]]; then
        bad "$label" "missing dir: $path"
        return
    fi
    local actual_owner
    actual_owner=$(stat -f "%Su:%Sg" "$path")
    if [[ "$actual_owner" != "$owner" ]]; then
        bad "$label" "$path owner $actual_owner, want $owner"
        return
    fi
    ok "$label"
}

# ------------------------------------------------------------------------

hdr "pkg registration"
if pkgutil --pkg-info com.monban.pkg >/dev/null 2>&1; then
    version=$(pkgutil --pkg-info com.monban.pkg | awk '/^version:/{print $2}')
    ok "com.monban.pkg registered (version $version)"
else
    bad "com.monban.pkg registered" "pkgutil --pkg-info found nothing"
fi

hdr "application bundle"
check_dir  "/Applications/Monban.app"                                        "root:wheel" "/Applications/Monban.app"
check_file "/Applications/Monban.app/Contents/MacOS/Monban"                  "root:wheel" ""     "  Monban binary"
check_file "/Applications/Monban.app/Contents/MacOS/monban-pam-helper"       "root:wheel" ""     "  monban-pam-helper in bundle"
check_file "/Applications/Monban.app/Contents/MacOS/pam_monban.so"           "root:wheel" ""     "  pam_monban.so in bundle"
check_dir  "/Applications/Monban.app/Contents/Resources/monban-auth.bundle"  "root:wheel"        "  monban-auth.bundle in bundle"

hdr "system-path components"
check_file "/usr/local/bin/monban-pam-helper"                                "root:wheel" "755"  "PAM helper at /usr/local/bin"
check_file "/usr/local/lib/pam/pam_monban.so"                                "root:wheel" "644"  "PAM module at /usr/local/lib/pam"
check_dir  "/Library/Security/SecurityAgentPlugins/monban-auth.bundle"       "root:wheel"        "Authorization plugin bundle"

hdr "sudo PAM gate"
if [[ -f /etc/pam.d/sudo_local ]]; then
    check_file "/etc/pam.d/sudo_local" "root:wheel" "444" "sudo_local file perms"
    if grep -q '# monban sudo gate' /etc/pam.d/sudo_local; then
        ok "sudo_local contains monban tag"
    else
        bad "sudo_local contains monban tag" "expected '# monban sudo gate' marker"
    fi
    if grep -q 'pam_monban.so' /etc/pam.d/sudo_local; then
        ok "sudo_local references pam_monban.so"
    else
        bad "sudo_local references pam_monban.so" "expected path to PAM module"
    fi
else
    bad "/etc/pam.d/sudo_local" "file missing — postinstall should have created it"
fi

hdr "authorizationdb rebind (admin dialogs)"
# Source the shared list so this stays in lockstep with postinstall.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../build/darwin/pkg/scripts/gated-rights.sh"
for right in "${GATED_RIGHTS[@]}"; do
    plist=$(security authorizationdb read "$right" 2>/dev/null)
    if [[ -z "$plist" ]]; then
        bad "authorizationdb $right" "security read returned empty"
        continue
    fi
    if grep -q 'evaluate-mechanisms' <<<"$plist" && grep -q 'monban-auth:auth' <<<"$plist"; then
        ok "$right rebound"
    else
        bad "$right rebound" "class or mechanism missing from plist output"
    fi
    backup="/Library/Security/SecurityAgentPlugins/$right.monban-backup"
    if [[ ! -f "$backup" ]]; then
        bad "  $right backup missing" "no $backup — uninstall would lose original"
    fi
done

hdr "no privileged daemon (Phase 2.5: daemon is gone)"
if launchctl print system/com.monban.privileged >/dev/null 2>&1; then
    bad "LaunchDaemon should NOT be loaded" "com.monban.privileged is registered — leftover from previous install?"
else
    ok "com.monban.privileged not loaded"
fi
if [[ -e /Library/LaunchDaemons/com.monban.privileged.plist ]]; then
    bad "Old LaunchDaemon plist should NOT be present" "/Library/LaunchDaemons/com.monban.privileged.plist exists"
else
    ok "No stale LaunchDaemon plist"
fi
if [[ -e /usr/local/libexec/monban-privileged ]]; then
    bad "Old daemon binary should NOT be present" "/usr/local/libexec/monban-privileged exists"
else
    ok "No stale daemon binary"
fi

hdr "user config (should exist if you've registered a YubiKey)"
if [[ -f "$HOME/.config/monban/credentials.json" ]]; then
    ok "~/.config/monban/credentials.json present"
else
    note "~/.config/monban/credentials.json missing" "register a YubiKey in the app to create it"
fi

# ------------------------------------------------------------------------

printf "\n%s%d passed%s" "$GREEN" "$pass" "$RESET"
[[ $fail -gt 0 ]] && printf ", %s%d failed%s" "$RED" "$fail" "$RESET"
[[ $warn -gt 0 ]] && printf ", %s%d warnings%s" "$YELLOW" "$warn" "$RESET"
printf "\n"

[[ $fail -gt 0 ]] && exit 1
exit 0
