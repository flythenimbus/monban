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
Go:          1.26
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

## 6a. Frontend Auth Pattern

Every config mutation requires FIDO2 re-auth. The frontend uses a consistent
pattern:

- `PinAuth` component (`components/PinAuth.tsx`) — reusable PIN input + "touch
  your security key..." waiting state. Props: `onSubmit(pin)`, `onCancel()`,
  optional `label`.
- Settings changes go through `AdminContext` pending change flow: toggle sets
  `pendingChange`, `PinAuth` appears, `confirmPendingChange(pin)` calls the API.
  Settings UI is disabled while a pending change is active. The toggle does NOT
  optimistically update — it stays in the current state until PIN confirmation.
- Vault add/remove and key remove each have their own PIN prompt state inline.
- `util/errors.ts` maps Go error strings to friendly messages (PIN errors,
  device errors, `rx error`, etc.).

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

// Config authentication key (HMAC signing):
configAuthKey  = HKDF-SHA256(ikm=masterSecret, salt=hmac_salt, info="monban-config-auth-v1")

// Per-vault lazy-strict key:
lazyStrictKey  = HKDF-SHA256(ikm=masterSecret, salt=hmac_salt, info="monban-lazy-strict-v1:<vaultPath>")

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

## 9. Config File

All config is in a single HMAC-signed file. Integrity is enforced by a
FIDO2-derived HMAC, not filesystem permissions. Every mutation (settings,
vaults, credentials) requires a fresh FIDO2 assertion (PIN + touch).

### Location

`~/.config/monban/credentials.json` (mode 0600)

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
  "vaults": [
    { "label": "Documents", "path": "/home/alice/Documents" },
    { "label": "secret.txt", "path": "/home/alice/secret.txt", "type": "file" }
  ],
  "vault_decrypt_modes": { "/home/alice/Documents": "lazy" },
  "open_on_startup": true,
  "config_counter": 42,
  "config_hmac": "<base64url>"
}
```

### HMAC tamper detection

`config_hmac` is HMAC-SHA256 over a canonical representation of all protected
fields (credentials, policy settings, vaults, decrypt modes, counter,
open_on_startup). Derived via `configAuthKey = HKDF(masterSecret, hmacSalt,
"monban-config-auth-v1")`. Verified on every unlock — tampered configs are
rejected.

### Rollback detection

`config_counter` is a monotonic counter incremented on every signed write.
An encrypted copy is stored at `~/.config/monban/counter.enc` (AES-256-GCM
with `encKey`). On unlock, if the config counter is behind the encrypted
counter, a rollback is detected. The user is warned but unlock proceeds
(they already proved FIDO2 possession). The counter is healed.

### Config directory locking

While the app is unlocked, `~/.config/monban/` is `chmod 0500` (no write).
This prevents any user-level process from deleting `counter.enc` or
`credentials.json`. The app temporarily restores `0700` when it needs to
write, then re-locks. If `counter.enc` is deleted while unlocked, the
device watcher detects it within 2 seconds and triggers an immediate lock.

### FIDO2 re-auth for all mutations

Every config write requires a fresh FIDO2 assertion (PIN + physical touch):
settings changes, vault add/remove, key add/remove, decrypt mode changes.
No mutation uses the in-memory master secret alone.

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

## 13. Code Hygiene Rules (Go)

These rules apply to all Go files under `desktop/` and `plugins/`.

### Layout: public on top, private at bottom
Every Go file with both exported and unexported functions/methods must be
organised as:

```
package foo

import ( ... )

// --- Types ---           (types, interfaces)
// --- Constants ---       (const blocks)
// --- Package vars ---    (package-level vars; optional)
// --- Public functions ---
//   (constructors, then exported funcs/methods in logical flow order)
// --- Private methods ---
//   (unexported methods on public types, in order of appearance in the public API)
// --- Private package-level helpers ---
//   (unexported free functions, small utilities)
```

Not every section header is required — omit the ones a file doesn't need —
but the ordering (public above private) is mandatory. Tests and `init()`
functions are exempt from ordering rules.

### Prefer stdlib over bespoke helpers
Before writing a small utility function, check whether the standard library
already provides it. In particular:

- `min` / `max` — built-in since Go 1.21 (don't write your own).
- `clear(slice)` — built-in for zeroing slices/maps (see `monban.ZeroBytes`).
- `slices.Contains` / `slices.Index` / `slices.Delete` — prefer over hand-rolled loops.
- `maps.Keys` / `maps.Values` — prefer over manual iteration.
- `bytes.Equal` / `hmac.Equal` / `subtle.ConstantTimeCompare` — never hand-roll
  byte comparison (timing-safe comparison is mandatory for MACs/hashes).
- `os.ReadFile` / `os.WriteFile` / `os.MkdirAll` — prefer over Open+Read+Close.
- `strings.TrimSpace` / `strings.Cut` / `strings.HasPrefix` — prefer over
  custom string manipulation.
- `errors.Is` / `errors.As` — prefer over string comparison of error messages.

Only write a helper if (a) no stdlib equivalent exists, (b) the stdlib form
is materially less readable at every call site, or (c) there's a concrete
reason to encapsulate the call (e.g. consistent error wrapping).

### Extract repeated patterns
If the same 5+ line block appears in 2+ places, extract it. Current shared
helpers to look at before writing new ones:

- `monban.hkdfKey(ikm, salt, info, label)` — every HKDF-SHA256 key
  derivation goes through this.
- `monban.randomBytes(n, label)` — all `crypto/rand`-backed random buffers.
- `monban.parallelOp(items, fn)` — per-file concurrent work with
  `runtime.NumCPU()` workers and first-error semantics. Both
  `encryptFilesIncremental` and `decryptFilesInPlace` use this.
- `monban.EncryptBytes` / `monban.DecryptBytes` — in-memory AES-256-GCM.
  Don't re-open `crypto/aes` + `cipher.NewGCM` directly; use these.

### Don't duplicate error-wrapping idioms
`fmt.Errorf("X: %w", err)` is idiomatic and *not* considered duplication —
leave it at each call site. Only extract when the surrounding logic (not
just the wrap) repeats.

### When not to extract
Cryptographic sequences that are 3–5 lines (nonce gen + `gcm.Seal`) are
kept inline deliberately — the intent is legible, and extraction adds
indirection without clarity gain. Only extract when it removes real
repetition (4+ sites) or encodes a non-obvious invariant.

## 14. Commands

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
