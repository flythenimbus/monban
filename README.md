# Monban

YubiKey-based encryption for macOS and Linux.

Monban encrypts your folders and individual files using AES-256-GCM, unlocked
only by a FIDO2 YubiKey assertion (PIN + physical touch). Everything is
encrypted in place. No external runtime dependencies. The lock is
cryptographic, not UI-based.

## How It Works

1. Register your YubiKey(s) through the app
2. Add folders or individual files to protect
3. On lock (app close, sleep, or logout), everything is encrypted in place
4. On unlock, enter your YubiKey PIN and touch the key to decrypt
5. Multiple YubiKeys can be registered for the same vaults

## Security

- **Encryption**: AES-256-GCM with streaming 64KB chunks. Files never load fully into memory.
- **Key derivation**: HKDF-SHA256 from the YubiKey's hmac-secret extension output. The secret never leaves the hardware.
- **Multi-key support**: A random master secret is wrapped (AES-256-GCM) by each YubiKey's derived key. Adding or removing keys never touches the encrypted files.
- **Auto-lock**: Vaults lock on sleep, logout, app quit, and SIGTERM/SIGINT.
- **Metadata protection**: Manifests are encrypted. Original filenames and directory structure are not visible when locked. Individual file vaults are stored in opaque directories with hashed names.
- **Crash safety**: A write-ahead journal ensures files are never lost during lock/unlock, even on power failure.
- **No plaintext key material touches the filesystem.**

## Force Authentication Mode

When enabled, the lock screen enters kiosk mode: fullscreen, no dock, no menu bar,
keyboard shortcuts blocked (Cmd+Q, Cmd+Tab, Force Quit). Requires macOS Accessibility
permission. The only way to unlock is to authenticate with a registered YubiKey.

## Requirements

A YubiKey with FIDO2 support (YubiKey 5 series or newer).

## Projects

- [`desktop/`](desktop/) - Desktop app (macOS, Linux) built with Wails v3, React, and Tailwind CSS v4
