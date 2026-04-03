# CLAUDE.md — Monban

## 1. Project Overview

Monban is a desktop post-login security layer for macOS and Linux that encrypts
user-configured folders and individual files using a YubiKey FIDO2 assertion
(PIN + physical touch) as the sole unlock mechanism. Files are encrypted with
AES-256-GCM using a key derived from the YubiKey's hmac-secret extension. The
lock is cryptographic — protected items contain only ciphertext until the
YubiKey authenticates. No FUSE, no external dependencies at runtime.

## 2. Architecture Decisions

### Why hmac-secret and not PIV
hmac-secret produces a device-bound deterministic output from a challenge, suitable
for key derivation. PIV signs arbitrary data but is not designed for KDF use.
hmac-secret never leaves the hardware.

### Why no per-vault salt
The vault passphrase is never stored. An attacker who can observe one passphrase
already has full YubiKey access. Per-vault salts provide no meaningful isolation.

### Why pure Go file-level encryption (not gocryptfs)
gocryptfs requires FUSE (macFUSE on macOS needs a kernel extension and on Apple
Silicon requires Recovery Mode; FUSE on Linux adds a runtime dependency). macFUSE
also has a commercial license. Pure Go encryption means zero user prerequisites.

### Why key wrapping for multi-key support
Different YubiKeys produce different hmac-secret values for the same salt.
A random master secret is generated once and wrapped (AES-256-GCM) by each
YubiKey's derived wrapping key. At unlock, we try unwrapping each credential's
wrapped key — the correct one succeeds via GCM authentication.

### Why the overlay window can be closeable
The lock is cryptographic. The window is UX only.

### Why Wails v3
v3 is the current development branch; v2 is in maintenance mode.

## 3. Platform Architecture

Platform-specific code is isolated via Go build tags (`//go:build darwin` /
`//go:build linux`). The split:

| Concern | macOS | Linux |
|---------|-------|-------|
| Sleep/session hooks | `hardening_darwin.go` — Cocoa NSWorkspace notifications | `hardening_linux.go` — D-Bus logind signals |
| Autostart | `autostart_darwin.go` — LaunchAgent plist | `autostart_linux.go` — XDG .desktop file |
| Window options | `main_darwin.go` — Mac titlebar, backdrop, tray icon | `main_linux.go` — defaults |

Everything else (crypto, vault, FIDO2, config, frontend) is platform-agnostic.

## 4. Tech Stack

```
Go:          1.25
Wails:       v3 alpha.74  (github.com/wailsapp/wails/v3)
go-libfido2: github.com/keys-pub/go-libfido2 v1.5.3
libfido2:    build-time dependency (brew install libfido2 / apt install libfido2-dev)
godbus:      github.com/godbus/dbus/v5 (Linux D-Bus, sleep/session hooks)
cbor:        github.com/fxamacker/cbor/v2 (COSE key parsing)
Node:        via Bun
Vite:        5.x
React:       18.x + TypeScript
Tailwind:    v4 (@tailwindcss/vite)
```

## 5. go-libfido2 API — Critical Gotchas

- `Attestation.PubKey` is raw `[]byte` COSE CBOR. NO `.ECDSA()` helper.
  Must parse with `fxamacker/cbor/v2` (see `cose.go`).
- `Assertion.AuthDataCBOR` — field is `AuthDataCBOR`, NOT `AuthData`.
  Contains CBOR-wrapped bytes that need unwrapping for signature verification.
- `AssertionOpts` — intentional typo in the library (missing 'r').
- `HMACSalt` is `[]byte` on `AssertionOpts`.
- `dev.Assertion()` returns `*Assertion` (single), not a slice.
- Device manages open/close internally — no exported `Close()` method.

## 6. Wails v3 Patterns

- **App init**: `application.New(application.Options{...})`
- **Services**: `application.NewService(&App{})` in `Services` slice
- **Window**: `app.Window.NewWithOptions(application.WebviewWindowOptions{...})`
- **Frontend calls**: `Call.ByName("monban.App.MethodName", args...)`
  from `@wailsio/runtime`
- **Do not use v2 imports** — they are incompatible.

## 7. Key Derivation

```
// First registration:
hmac_salt      = random 32 bytes (stored in config, immutable)
masterSecret   = random 64 bytes

// Per-key wrapping:
wrappingKey    = HKDF-SHA256(ikm=hmacSecret, salt=hmac_salt, info="monban-keywrap-v1")
wrapped_key    = AES-256-GCM(key=wrappingKey, plaintext=masterSecret)

// File encryption key:
encKey         = HKDF-SHA256(ikm=masterSecret, salt=hmac_salt, info="monban-fileenc-v1")

// At unlock:
assertion      → hmacSecret
wrappingKey    = HKDF(hmacSecret, hmac_salt, "monban-keywrap-v1")
masterSecret   = AES-GCM-Unwrap(wrappingKey, credential.wrapped_key)
encKey         = HKDF(masterSecret, hmac_salt, "monban-fileenc-v1")
// encKey used for AES-256-GCM file encryption/decryption
```

**WARNING: Changing hmac_salt, rp_id, or HKDF info strings renders all vaults
permanently inaccessible.**

## 8. File Encryption Format

- Streaming AES-256-GCM in 64KB chunks
- Per-file: 12-byte random nonce + 4-byte chunk size header
- Chunk nonce = file nonce XOR chunk index (no extra random bytes needed)
- Never loads whole file into memory
- Parallel workers (runtime.NumCPU goroutines)

## 9. Config Files

Config is split into two files for security. Cryptographic material is stored
in a root-owned system config that user-level processes cannot tamper with.

### Secure config (root-owned)

Location: `/Library/Application Support/monban/credentials.json` (macOS)
         `/etc/monban/credentials.json` (Linux)
Mode: `root:wheel 0644` (world-readable, root-writable)

```jsonc
{
  "rp_id": "monban.local",
  "hmac_salt": "<base64url, immutable>",
  "credentials": [
    {
      "label": "YubiKey 5C",
      "credential_id": "<base64url>",
      "public_key_x": "<base64url>",
      "public_key_y": "<base64url>",
      "wrapped_key": "<base64url>"
    }
  ],
  "force_authentication": true,
  "sudo_gate": "off"
}
```

Written via OS-specific root escalation (osascript on macOS, pkexec on Linux).
Changes on key registration/removal and security setting toggles.

### User config (user-owned)

Location: `~/.config/monban/config.json` (mode 0600)

```jsonc
{
  "vaults": [
    {
      "label": "Documents",
      "path": "/home/alice/Documents"
    },
    {
      "label": "secret.txt",
      "path": "/home/alice/secret.txt",
      "type": "file"
    }
  ],
  "settings": {
    "open_on_startup": true
  }
}
```

A malicious user-level process can edit this file, but the worst outcome is
losing the vault list (annoying but recoverable — encrypted files remain on
disk). Credentials, crypto material, and security settings (force_authentication,
sudo_gate) in the secure config are untouchable without root.

## 9a. Sudo Gate (PAM Integration)

Monban can gate `sudo` behind YubiKey FIDO2 authentication via `pam_exec.so`.

Modes:
- **off** — no PAM integration
- **default** — `auth sufficient` on sudo only — YubiKey success skips password, failure falls through
- **strict** — `auth required` on both sudo and su — YubiKey must succeed, no password fallback. Also gates `/etc/pam.d/su` to prevent root user activation bypass.

Components:
- `cmd/pam-helper/` — standalone binary invoked by PAM, reads secure config,
  prompts for PIN via `/dev/tty`, performs FIDO2 assertion + signature verification
- `internal/monban/pam.go` — PAM line install/removal with root escalation
- `pam_darwin.go` / `pam_linux.go` — OS-specific privilege escalation

## 10. Vault Types

### Folder vaults (default)
Encrypt all files in a directory into `.monban-data/` with hashed filenames.
An encrypted manifest maps hashed names back to originals.

### File vaults (`type: "file"`)
Encrypt a single file into an opaque directory next to the original:
```
/path/to/.monban-<hash16>/
  data.enc                  — encrypted file content
  .monban-manifest.enc      — encrypted manifest (original name, perms, modtime)
```
The `<hash16>` is the first 16 hex chars of SHA-256(absolute file path).
The original filename is not visible on disk when locked. The manifest
format is the same as folder vaults (single-entry `Manifest` struct).

The `VaultEntry.Type` field is `"file"` for file vaults. Omitted or empty
defaults to folder behavior (backward compatible).

## 11. Vault Safety — Write-Ahead Journal

Lock/unlock use a journal for crash recovery:
1. Write journal state before each phase
2. Never delete a copy until the other copy is verified
3. On startup, check for stale journals and recover

## 12. cgo Build Environment

```bash
# macOS (Apple Silicon):
CGO_CFLAGS="-I/opt/homebrew/include"
CGO_LDFLAGS="-L/opt/homebrew/lib -lfido2"
# Also links Cocoa framework for hardening_darwin.go (sleep/logout hooks)

# Linux:
CGO_LDFLAGS="-lfido2"
# Requires: libfido2-dev libgtk-3-dev libwebkit2gtk-4.1-dev
```

## 13. Commands

```bash
# Generate Wails bindings (needed before frontend build)
wails3 generate bindings

# Dev mode
wails3 dev

# Production build
wails3 build

# macOS: Install LaunchAgent
cp setup/com.monban.agent.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.monban.agent.plist

# Linux: packaging (deb/rpm/AppImage)
task linux:package
```
