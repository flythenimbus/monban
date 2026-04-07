<p align="center">
  <img src="website/public/favicon.png" alt="Monban" />
</p>

# Monban

Security key encryption for macOS and Linux.

Monban encrypts your folders and individual files using AES-256-GCM, unlocked
only by a FIDO2 security key assertion (PIN + physical touch). Everything is
encrypted in place. No external runtime dependencies. The protection is real
encryption, not just a hidden folder.

## Features

- **Universal security key support**: works with any FIDO2 key that supports the hmac-secret extension
- **Multiple keys per vault**: register as many security keys as you want, so losing one doesn't mean losing access
- **Post-login 2FA**: opt-in kiosk lock screen that requires security key authentication after OS sign-in
- **File and folder encryption**: encrypt individual files or entire folders, all in place
- **Protect sudo and su**: prevent privilege escalation without security key authentication
- **Easy backup**: export your vault configuration to recover access and prevent lockout

## How It Works

1. Register your security key(s) through the app
2. Add folders or individual files to protect
3. On lock (app close, sleep, or logout), everything is encrypted in place
4. On unlock, enter your PIN and touch the key to decrypt

## Security

- **Encryption**: AES-256-GCM with streaming 64KB chunks. Files never load fully into memory.
- **Key derivation**: HKDF-SHA256 from the FIDO2 hmac-secret extension output. The secret never leaves the hardware.
- **Key wrapping**: A random master secret is wrapped (AES-256-GCM) by each security key's derived key. Adding or removing keys never touches the encrypted files.
- **Auto-lock**: Vaults lock on sleep, logout, app quit, and SIGTERM/SIGINT.
- **Metadata protection**: Manifests are encrypted. Original filenames and directory structure are not visible when locked. Individual file vaults are stored in opaque directories with hashed names.
- **Crash safety**: A write-ahead journal ensures files are never lost during lock/unlock, even on power failure.
- **No plaintext key material touches the filesystem.**

## Supported Keys

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

## Donate

Monban is free and open source. If you find it useful, consider supporting development with Monero.

<p align="center">
  <img src="website/public/monero.png" alt="Monero donation QR code" width="200" />
</p>

```
4AC3txuTwFm4fkamoYeK47c9EpnPwbreHNxJeKDYHiDNN6weD5vVA4BCH1azQhSxa6JjereuVpt21Pu2MyRDFDNNH6KGnWq
```

## License

Monban is licensed under the [GNU General Public License v3.0](LICENSE).
