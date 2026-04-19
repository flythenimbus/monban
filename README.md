<p align="center">
  <img src="website/public/favicon.png" alt="Monban" />
</p>

# Monban

Lock your files with a security key. macOS and Linux.

Monban encrypts your stuff using AES-256-GCM. You unlock it with a FIDO2 security key - enter your PIN, tap the key. Files get encrypted right where they are. No extra dependencies. This is real encryption, not just hiding a folder.

## Features

👉 **Any FIDO2 key works** - if it supports hmac-secret, you're good

👉 **Multiple keys per vault** - register backups so losing one key isn't the end of the world

👉 **Lock screen after login** - optional 2FA screen that blocks access until you tap your key

👉 **Files or folders** - encrypt whatever you want, right in place

👉 **Lazy mode** - vaults can stay locked until you actually need them, or require a fresh PIN + tap every time

👉 **Admin gate** - sudo and system admin dialogs require your security key (su too, with a bit of recovery-mode setup — see below)

👉 **Easy backup** - export your vault config so you don't get locked out

## How It Works

1. Plug in your security key and register it
2. Pick files or folders to protect
3. When the app closes, your machine sleeps, or you log out - everything gets encrypted
4. To unlock, enter your PIN and tap your key
5. Want more control? Set vaults to lazy (decrypt on demand) or strict (fresh PIN + tap every time)

## Security

- **Encryption** - AES-256-GCM, streamed in 64KB chunks. Files never fully load into memory.
- **Key derivation** - HKDF-SHA256 from your key's hmac-secret output. The secret never leaves the hardware.
- **Key wrapping** - a random master secret gets wrapped by each key. Adding or removing keys doesn't re-encrypt your files.
- **Auto-lock** - vaults lock on sleep, logout, quit, and kill signals.
- **Metadata hidden** - filenames and folder structure are invisible when locked. Single-file vaults use hashed names.
- **Crash safe** - a write-ahead journal means files are never lost, even on power failure.
- **Strict mode keys** - unique encryption key per vault, only lives in memory during auth, zeroed right after.
- **No key material ever hits the filesystem in plaintext.**

## Supported Keys

- YubiKey (5 series or newer)
- Google Titan
- Nitrokey (FIDO2, 3A)
- CanoKey
- SoloKeys
- Feitian (BioPass, ePass)
- OnlyKey

## Advanced Hardening (macOS only)

By default the installer can't touch `/etc/pam.d/su`. Apple locks it behind SIP. That leaves one escalation path open: if an attacker knows your login password, they can run `dsenableroot` (we can't gate it since Apple's code crashes when we try) and then `su -` into root without ever touching your key.

Closing that path requires a one-time trip through Recovery Mode. You're accepting a weaker SIP stance in exchange for a stricter root boundary. If you lose your key, you'll need the same recovery-mode trip to back out.

1. Reboot holding the power button, pick **Options** → **Continue**.
2. Utilities → Terminal → `csrutil authenticated-root disable`, enter your password, reboot.
3. Back in macOS: `sudo mount -uw /`
4. Append the same gate line to su's PAM config:
   ```
   echo 'auth sufficient /usr/local/lib/pam/pam_monban.so # monban su gate' \
     | sudo tee -a /etc/pam.d/su > /dev/null
   ```
5. Reseal the system snapshot: `sudo bless --folder /System/Library/CoreServices --bootefi --create-snapshot`
6. Reboot.

Now `su` requires your key too. `dsenableroot` can still set a root password, but the password alone won't let anyone become root - they'd need to tap your key. Major macOS upgrades reset `/etc/pam.d/su`; you'll need to redo steps 3-6 after them.

To undo: same dance, but edit the file to remove the monban line (or re-enable SIP with `csrutil enable`).

## Projects

- [`desktop/`](desktop/) - Desktop app (macOS, Linux). Wails v3 + React + Tailwind v4.
- [`website/`](website/) - Marketing site. Built with Astro.

## Contributing

Want to help? Open an issue first so we can talk about it, then send a PR.

## Donate

Monban is free and open source. If it's useful to you, toss some Monero our way.

<p align="center">
  <img src="website/public/monero.png" alt="Monero donation QR code" width="200" />
</p>

```
4AC3txuTwFm4fkamoYeK47c9EpnPwbreHNxJeKDYHiDNN6weD5vVA4BCH1azQhSxa6JjereuVpt21Pu2MyRDFDNNH6KGnWq
```

## License

[GNU General Public License v3.0](LICENSE)
