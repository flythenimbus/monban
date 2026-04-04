<p align="center">
  <img src="website/public/favicon.png" alt="Monban" />
</p>

# Monban

Security key encryption for macOS and Linux.

Monban encrypts your folders and individual files using AES-256-GCM, unlocked
only by a FIDO2 security key assertion (PIN + physical touch). Everything is
encrypted in place. No external runtime dependencies. The lock is
cryptographic, not UI-based.

## How It Works

1. Register your security key(s) through the app
2. Add folders or individual files to protect
3. On lock (app close, sleep, or logout), everything is encrypted in place
4. On unlock, enter your PIN and touch the key to decrypt
5. Multiple security keys can be registered for the same vaults

## Security

- **Encryption**: AES-256-GCM with streaming 64KB chunks. Files never load fully into memory.
- **Key derivation**: HKDF-SHA256 from the FIDO2 hmac-secret extension output. The secret never leaves the hardware.
- **Multi-key support**: A random master secret is wrapped (AES-256-GCM) by each security key's derived key. Adding or removing keys never touches the encrypted files.
- **Auto-lock**: Vaults lock on sleep, logout, app quit, and SIGTERM/SIGINT.
- **Metadata protection**: Manifests are encrypted. Original filenames and directory structure are not visible when locked. Individual file vaults are stored in opaque directories with hashed names.
- **Crash safety**: A write-ahead journal ensures files are never lost during lock/unlock, even on power failure.
- **No plaintext key material touches the filesystem.**

## Force Authentication Mode

When enabled, the lock screen enters kiosk mode: fullscreen, no dock, no menu bar,
keyboard shortcuts blocked (Cmd+Q, Cmd+Tab, Force Quit). Requires macOS Accessibility
permission. The only way to unlock is to authenticate with a registered security key.

## Supported Keys

Any FIDO2 security key with hmac-secret extension support, including:

- YubiKey (5 series or newer)
- Google Titan
- Nitrokey (FIDO2, 3A)
- CanoKey
- SoloKeys
- Feitian (BioPass, ePass)
- OnlyKey

## Projects

- [`desktop/`](desktop/) - Desktop app (macOS, Linux) built with Wails v3, React, and Tailwind CSS v4
- [`website/`](website/) - Marketing site built with Astro

## Contributing

Contributions are welcome. Please open an issue to discuss your idea before submitting a pull request.

## Sponsor

If you find Monban useful, consider [sponsoring the project](https://github.com/flythenimbus/monban/sponsor) to support ongoing development.

## License

Monban is licensed under the [GNU General Public License v3.0](LICENSE).
