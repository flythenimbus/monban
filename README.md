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

## Projects

- [`desktop/`](desktop/) - Desktop app (macOS, Linux). Wails v3 + React + Tailwind v4.
- [`website/`](website/) - Marketing site. Built with Astro.

## Contributing

Want to help? Open an issue first so we can talk about it, then send a PR.

### What you need

- Go 1.26+
- Bun
- Wails v3 CLI: `go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-alpha.74`
- libfido2 — `brew install libfido2` on macOS, `apt install libfido2-dev libgtk-3-dev libwebkit2gtk-4.1-dev` on Debian/Ubuntu
- Messing with plugins on macOS? You'll also want Xcode command-line tools

### Getting set up

```bash
git clone https://github.com/flythenimbus/monban.git
cd monban/desktop
```

If you just want to build and run the app, you're done - the committed dev pubkey already matches. If you plan to build and sign plugins locally, you need your own keypair:

```bash
task common:build:monban-sign
./bin/monban-sign generate-key \
  ./cmd/monban-sign/testkeys/dev-release.pub \
  ./cmd/monban-sign/testkeys/dev-release.key
```

The `.key` is git-ignored and stays on your machine. If you regenerate, update `defaultDevPubKeyHex` in `internal/plugin/devkey.go` to match - and keep that change off your PR, the committed one stays authoritative.

### Running it

```bash
task dev              # Wails dev server, DevTools on
task test             # Go tests
task lint             # golangci-lint + bun lint
```

Testing the plugin install flow? Pick the mode that matches what your plugin is signed with:

```bash
task dev              # trusts your dev key - for plugins you built locally
task dev:prodkey      # trusts the prod key - for real CI-signed releases
```

### Building a plugin

Reference plugin is `plugins/admin_gate` (macOS only, gates sudo behind your key):

```bash
cd plugins/admin_gate
./build.sh
```

Signs with your dev key, outputs everything into `dist/`. Then **Admin → Plugins → Install** in the running app. For fully local testing without going through a GitHub release, `task plugin:release:test` cuts a disposable tag.

### Security tests

Path-escape and install guards live in `desktop/internal/plugin/security_test.go`:

```bash
cd desktop
go test ./internal/plugin/ -run 'TestResolvePluginPath|TestInstaller' -v
```

### Before your PR

- `task test` and `task lint` pass
- Nothing under `testkeys/*.key` shows up in your diff - the dev private key is per-developer, never commit it
- Touched the plugin loader or verifier? Add a case to `security_test.go`

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
