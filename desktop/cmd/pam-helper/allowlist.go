package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"

	"monban/internal/monban"
)

// authorizedKeysPath is the admin-pinned allowlist of FIDO2 credentials
// permitted to satisfy monban's PAM gate. When the file is absent the
// helper falls back to legacy behaviour — any credential registered in
// the invoking user's credentials.json works. When it is present and
// root-owned, only credentials whose (public_key_x, public_key_y) pair
// appears in the allowlist are accepted — H3's enterprise hardening
// against a sudoer replacing their own credentials.json with a
// registration to a random YubiKey.
const authorizedKeysPath = "/etc/monban/authorized_keys.json"

// authorizedKeys is the on-disk schema. Keeping it a bare list of
// labelled pubkey pairs makes it trivial for `security/monban` admin
// tooling to append an entry when provisioning a new key, without
// touching each user's credentials.json.
type authorizedKeys struct {
	Authorized []authorizedKey `json:"authorized_credentials"`
}

type authorizedKey struct {
	Label       string `json:"label,omitempty"`
	PublicKeyX  string `json:"public_key_x"`
	PublicKeyY  string `json:"public_key_y"`
}

// filterAuthorized returns the subset of creds whose pubkey pair is in
// the admin allowlist. If no allowlist is present on disk, creds is
// returned unchanged (legacy behaviour). If the file exists but is
// unreadable or not root-owned, returns an error — a misprovisioned
// allowlist must fail closed rather than silently fall back.
func filterAuthorized(creds []monban.CredentialEntry) ([]monban.CredentialEntry, error) {
	st, err := os.Stat(authorizedKeysPath)
	if errors.Is(err, os.ErrNotExist) {
		return creds, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat allowlist: %w", err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 {
		return nil, fmt.Errorf("%s must be root-owned", authorizedKeysPath)
	}
	raw, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	var ak authorizedKeys
	if err := json.Unmarshal(raw, &ak); err != nil {
		return nil, fmt.Errorf("parse allowlist: %w", err)
	}
	if len(ak.Authorized) == 0 {
		// Empty allowlist = deny everything. Explicit intent.
		return nil, nil
	}
	type key struct{ x, y string }
	allowed := make(map[key]bool, len(ak.Authorized))
	for _, k := range ak.Authorized {
		allowed[key{k.PublicKeyX, k.PublicKeyY}] = true
	}
	filtered := creds[:0:0]
	for _, c := range creds {
		if allowed[key{c.PublicKeyX, c.PublicKeyY}] {
			filtered = append(filtered, c)
		}
	}
	return filtered, nil
}
