# macOS Install Plan — unsigned `.pkg` + LaunchDaemon + Homebrew cask

## Goal

Replace the current macOS install flow (drop `.app` in `/Applications`, then in-app `osascript` prompts on first admin-gate toggle) with a single `.pkg` that pre-places all system-path components at install time, and a root LaunchDaemon that lets the app perform privileged writes thereafter without another password prompt. Distribute primarily via a Homebrew cask that wraps the `.pkg`.

No code signing. No notarization. Ad-hoc `codesign --sign -` is kept for TCC identity stability.

## Scope

**In:**
- Universal `.pkg` built in CI, attached to every release.
- System-path install of helper binary, PAM module, auth plugin, and (Phase 2) privileged daemon.
- LaunchDaemon for runtime PAM file edits, gated by FIDO2 assertion in the IPC protocol.
- GoReleaser-managed Homebrew cask pointing at the `.pkg`.

**Out:**
- Apple Developer ID signing (philosophical, per project memory on Apple dependency minimization).
- Apple notarization.
- `SMAppService` — raw `/Library/LaunchDaemons/` plist only, no Apple-blessed daemon registration.

**Stays the same:**
- `.app` bundle layout, FIDO2 crypto, PAM module, authorization plugin internals.
- Existing app ↔ pam-helper IPC socket (`~/.config/monban/monban.sock`). The new privileged daemon is a separate socket on a separate protocol.
- Existing `osascript` privileged-write path — kept as fallback when the daemon isn't installed (e.g. users who continue to drop the `.app` manually).

## Checkpoints

Three phases, each reviewable independently. Don't proceed past a checkpoint until it's merged.

| Phase | Deliverable | Checkpoint criterion |
|-------|-------------|----------------------|
| 1 | `.pkg` artifact on every release, pre-placing all current system-path files | Fresh macOS VM: `.pkg` installs cleanly, app launches, `admin_gate` toggle still works (via existing `osascript` fallback) |
| 2 | LaunchDaemon replaces `osascript` for `admin_gate` toggles | Fresh macOS VM with Phase 1 + Phase 2 installed: toggling `admin_gate` from the GUI shows only PIN + touch, no macOS password dialog. Users without the daemon still get the osascript path |
| 3 | `brew install --cask monban` works against a tap repo | Fresh macOS VM: `brew tap flythenimbus/tap && brew install --cask monban` installs and `brew uninstall --cask monban` cleans up fully |

---

## Phase 1 — Build an unsigned `.pkg` in CI

### Intent

One new release artifact. No runtime behavior change. Users installing via the `.pkg` get helper/module/plugin pre-placed in system paths, so the existing `osascript`-driven binary placement on first admin-gate toggle becomes a no-op (files already exist). Toggling `admin_gate` still uses `osascript` to write `/etc/pam.d/sudo_local` — Phase 2 replaces that.

### New files

```
desktop/build/darwin/pkg/
  distribution.xml              # productbuild distribution descriptor
  scripts/
    preinstall                  # stop running Monban + any previous daemon (prep for Phase 2)
    postinstall                 # chmod/chown fixups (daemon bootstrap lives in Phase 2)
  resources/
    welcome.html                # shown on installer first screen
    license.txt                 # project license
```

### New Taskfile target

`desktop/build/darwin/Taskfile.yml`:

```yaml
pkg:
  summary: Builds an unsigned .pkg installer containing the .app + helper/module/plugin
  deps:
    - task: package:universal     # existing: produces bin/Monban.app
  vars:
    VERSION: '{{.VERSION | default "0.0.0"}}'
    PKG_ROOT: "{{.BIN_DIR}}/pkg-root"
    COMPONENT_PKG: "{{.BIN_DIR}}/Monban-component.pkg"
    FINAL_PKG: "{{.BIN_DIR}}/Monban-{{.VERSION}}.pkg"
  cmds:
    - rm -rf "{{.PKG_ROOT}}"
    - mkdir -p "{{.PKG_ROOT}}/Applications"
    - mkdir -p "{{.PKG_ROOT}}/usr/local/bin"
    - mkdir -p "{{.PKG_ROOT}}/usr/local/lib/pam"
    - mkdir -p "{{.PKG_ROOT}}/Library/Security/SecurityAgentPlugins"
    - cp -R "{{.BIN_DIR}}/Monban.app" "{{.PKG_ROOT}}/Applications/"
    - cp "{{.BIN_DIR}}/monban-pam-helper" "{{.PKG_ROOT}}/usr/local/bin/"
    - cp "{{.BIN_DIR}}/pam_monban.so" "{{.PKG_ROOT}}/usr/local/lib/pam/"
    - cp -R "{{.BIN_DIR}}/monban-auth.bundle" "{{.PKG_ROOT}}/Library/Security/SecurityAgentPlugins/"
    - pkgbuild
        --root "{{.PKG_ROOT}}"
        --identifier com.monban.pkg
        --version "{{.VERSION}}"
        --scripts build/darwin/pkg/scripts
        --install-location /
        "{{.COMPONENT_PKG}}"
    - productbuild
        --distribution build/darwin/pkg/distribution.xml
        --resources build/darwin/pkg/resources
        --package-path "{{.BIN_DIR}}"
        "{{.FINAL_PKG}}"
    - rm "{{.COMPONENT_PKG}}"
```

### `distribution.xml` (minimal)

```xml
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>Monban</title>
  <welcome file="welcome.html"/>
  <license file="license.txt"/>
  <options customize="never" require-scripts="true"/>
  <choices-outline>
    <line choice="default"/>
  </choices-outline>
  <choice id="default">
    <pkg-ref id="com.monban.pkg"/>
  </choice>
  <pkg-ref id="com.monban.pkg">Monban-component.pkg</pkg-ref>
</installer-gui-script>
```

### `scripts/postinstall` (Phase 1 version)

```bash
#!/bin/bash
set -e
chmod 0755 /usr/local/bin/monban-pam-helper
chmod 0644 /usr/local/lib/pam/pam_monban.so
chmod -R a+rX /Library/Security/SecurityAgentPlugins/monban-auth.bundle
# Intentionally does NOT modify /etc/pam.d/sudo_local.
# admin_gate starts "off"; first toggle writes the PAM line via the existing
# osascript path (Phase 1) or the privileged daemon (Phase 2).
exit 0
```

### `scripts/preinstall`

```bash
#!/bin/bash
# Quit a running app so its binaries can be replaced.
pkill -x Monban 2>/dev/null || true
exit 0
```

### CI changes

`.github/workflows/release.yml`, `build-darwin` job. After `task darwin:create:app:bundle`:

```yaml
- name: Build .pkg
  working-directory: desktop
  run: task darwin:pkg VERSION=${GITHUB_REF_NAME#v}

- uses: actions/upload-artifact@v4
  with:
    name: darwin-pkg
    path: desktop/bin/Monban-*.pkg
```

In the `release` job:
- Add `darwin-pkg` via the existing `merge-multiple: true` download pattern (already picks it up).
- Extend the "Generate combined checksums" step: `sha256sum Monban-*.pkg >> checksums.txt 2>/dev/null || true`.

### Phase 1 acceptance

- [ ] `Monban-<version>.pkg` present in release assets.
- [ ] Fresh macOS (Sequoia) VM: double-click the `.pkg` → right-click Open (unsigned) → installer runs to completion.
- [ ] `/Applications/Monban.app` exists; `/usr/local/bin/monban-pam-helper`, `/usr/local/lib/pam/pam_monban.so`, `/Library/Security/SecurityAgentPlugins/monban-auth.bundle` all exist with correct perms.
- [ ] Launching `Monban.app`, registering a YubiKey, and toggling `admin_gate` → still works via existing `osascript` path (one password dialog per toggle — unchanged behavior).
- [ ] `.zip` artifact still present and still works for users who don't use the `.pkg`.

### Phase 1 risks / things to verify in review

- Universal binary path: current `.goreleaser-darwin.yml` emits a universal binary via `universal_binaries: replace: true`. Verify `task darwin:pkg` depends on the universal output, not a single-arch build.
- `productbuild` is strict about missing welcome/license files — CI failures here are loud but confusing if paths drift.
- The `.pkg` is unsigned → fresh downloads trigger Gatekeeper. Document the "System Settings → Privacy & Security → Open Anyway" step in the README as part of this phase.

---

## Phase 2 — LaunchDaemon for runtime PAM edits

### Intent

Eliminate every remaining in-app `osascript` prompt by moving privileged writes into a root daemon that the app talks to over a Unix socket. The daemon enforces the same security invariant as every other config mutation: nothing happens without a fresh FIDO2 assertion.

### New components

```
desktop/cmd/monban-privileged/
  main.go                       # LaunchDaemon entry point
desktop/internal/monban/
  privileged_protocol.go        # request/response types, socket path
  privileged_client.go          # app-side client (used by pam.go)
  privileged_server.go          # daemon-side handler
desktop/build/darwin/
  com.monban.privileged.plist   # LaunchDaemon plist
```

Add `monban-privileged` to `common:build:*` Taskfile targets so it's built alongside the PAM helper and ends up in the `.app` bundle.

### Daemon responsibilities

- Binary: `/usr/local/libexec/monban-privileged`, owner `root:wheel`, mode `0755`.
- Launched by `launchd` at boot via `/Library/LaunchDaemons/com.monban.privileged.plist`.
- Listens on `/var/run/monban-privileged.sock`, owner `root:wheel`, mode `0666`. Protocol-level auth (FIDO2), not filesystem auth — any user can connect, but only a valid assertion gets work done.
- Accepts exactly three operations, each authenticated by a FIDO2 assertion over a server-issued challenge:
  1. `install_gate(user, mode)` — write `/etc/pam.d/sudo_local`, `/etc/pam.d/authorization`, configure `authorizationdb` rights.
  2. `remove_gate(user)` — reverse of install.
  3. `uninstall(user)` — full cleanup for the app's Uninstall button.

### Protocol

Two-message flow per operation:

```
// 1. challenge
C → S: {"type":"challenge","user":"alice"}
S → C: {"challenge":"<32 random bytes b64url>"}

// 2. operation
C → S: {
  "type":"install_gate",
  "user":"alice",
  "mode":"strict",
  "challenge":"<same b64url>",
  "assertion":{
    "credential_id":"...",
    "auth_data_cbor":"...",
    "sig":"..."
  }
}
S → C: {"ok":true}  |  {"ok":false,"error":"..."}
```

Per-connection state machine:
- Connection accepted → generate 32 random bytes → hold as pending challenge → emit.
- Next message must reference that exact challenge; anything else → close.
- On verify success → perform operation → respond → close.
- On verify fail → respond error → close.

### Verification logic (daemon side)

1. Resolve `<user_home>/.config/monban/credentials.json` via `user.Lookup(request.user)`.
2. Load secure config with existing `monban.LoadSecureConfig` (use user-scoped reader variant).
3. Reuse `monban.VerifyAssertionWithSalt` — same function that the PAM helper uses today. No new crypto.
4. Key gotcha: the assertion's `clientDataHash` must bind to the challenge. The client computes `clientDataHash = SHA256("monban-privileged-v1" || challenge)` and the FIDO2 assertion call uses that as the client data hash. Daemon recomputes and compares.

### LaunchDaemon plist

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.monban.privileged</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/libexec/monban-privileged</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardErrorPath</key><string>/var/log/monban-privileged.err</string>
</dict>
</plist>
```

Decision deferred: always-running vs socket-activated. Default: always-running (simpler, ~5 MB RSS). Revisit only if RAM complaints surface.

### Postinstall additions (extends Phase 1)

Append to `scripts/postinstall`:

```bash
mkdir -p /usr/local/libexec
cp /Applications/Monban.app/Contents/MacOS/monban-privileged /usr/local/libexec/
chmod 0755 /usr/local/libexec/monban-privileged

cp /Applications/Monban.app/Contents/Resources/com.monban.privileged.plist \
   /Library/LaunchDaemons/
chown root:wheel /Library/LaunchDaemons/com.monban.privileged.plist
chmod 0644 /Library/LaunchDaemons/com.monban.privileged.plist

launchctl bootstrap system /Library/LaunchDaemons/com.monban.privileged.plist || true
```

And extend `scripts/preinstall`:

```bash
launchctl bootout system /Library/LaunchDaemons/com.monban.privileged.plist 2>/dev/null || true
```

The `.app` bundle's `create:app:bundle` task must also copy the plist into `Monban.app/Contents/Resources/` so postinstall can find it.

### App-side refactor

- `internal/monban/pam.go`:
  - Add a helper `usePrivilegedDaemon() bool` → `true` if `/var/run/monban-privileged.sock` exists *and* a handshake ping succeeds.
  - `InstallSudoGate(mode)` → if daemon available, call `privileged_client.InstallGate(mode, userAssertion)`; else current `osascript` path.
  - Same for `RemoveSudoGate()` and the batch auth plugin path.
- `internal/app/app_settings.go`: the admin_gate toggle already obtains a FIDO2 assertion through the pending-change flow. Thread the assertion through to the privileged client.
- `internal/app/platform_hooks.go` (already-modified in working tree): confirm no conflict with new client wiring.

### Phase 2 acceptance

- [ ] Fresh macOS VM with `.pkg` installed: `launchctl list | grep monban` shows `com.monban.privileged`.
- [ ] Toggling `admin_gate` off → default: single PIN prompt + single touch. No macOS password dialog.
- [ ] Toggling `admin_gate` default → strict: single PIN prompt + single touch.
- [ ] Uninstall flow: single PIN prompt + touch, everything cleaned up.
- [ ] Sanity: manually send a raw JSON request to the socket without a valid assertion → daemon rejects with error, no file change on disk.
- [ ] Fallback: on a system with no daemon (manual `.app` drop-in), admin_gate toggles still work via `osascript`.
- [ ] Daemon survives app crash and laptop sleep/resume.

### Phase 2 risks / things to verify in review

- **Lockout risk**: a bug in the daemon's PAM-file writer can break `sudo` entirely. Mitigations: never truncate `/etc/pam.d/sudo_local` to empty, always write via tmpfile + atomic rename, unit-test the file builder against a corpus of existing-content variants, keep the current `osascript` implementation as a live fallback for at least one release after Phase 2 ships.
- **Replay**: challenges are per-connection and never reused. Daemon must close the connection after response to prevent a second operation on the same challenge.
- **User-home resolution**: daemon runs as root, `user.Lookup()` gives a home path. If the user passes a bogus `user` field, daemon operates on a different user's config. Check: `user` field must match one of the currently-logged-in console users (via `who` or stat of `/dev/console`).
- **Assertion rebinding**: the client data hash *must* bind to the daemon's challenge, or an attacker could replay an assertion captured from the regular app unlock path. Tests should attempt exactly this replay and confirm rejection.

---

## Phase 3 — Homebrew cask via GoReleaser

### Intent

`brew install --cask monban` on macOS, formula published to a tap repo, auto-updated on every release. Users get SHA-256 pinning without Apple being involved.

### Prereq (one-time, manual)

- Create `github.com/flythenimbus/homebrew-tap` repo with a `Casks/` directory.
- Create a PAT with `contents: write` scoped to that repo, store as `HOMEBREW_TAP_TOKEN` in this repo's Actions secrets.

### GoReleaser changes

The current darwin workflow runs `goreleaser build` (build-only). Homebrew cask publishing requires `goreleaser release`, so Phase 3 has to promote the darwin job from build-only to full release mode, or split the work across jobs.

Recommended: unify on `goreleaser release` for darwin.

Add to `.goreleaser-darwin.yml`:

```yaml
release:
  github:
    owner: flythenimbus
    name: monban
  extra_files:
    - glob: ./bin/Monban-*.pkg
    - glob: ./release/*.zip

homebrew_casks:
  - name: monban
    binary: Monban
    repository:
      owner: flythenimbus
      name: homebrew-tap
      branch: main
      token: "{{ .Env.HOMEBREW_TAP_TOKEN }}"
    directory: Casks
    homepage: https://github.com/flythenimbus/monban
    description: "Desktop security layer gating folders/files behind a YubiKey FIDO2 assertion"
    license: "MIT"  # confirm project license
    url:
      template: "https://github.com/flythenimbus/monban/releases/download/{{ .Tag }}/Monban-{{ .Version }}.pkg"
    uninstall:
      pkgutil: "com.monban.pkg"
      launchctl: "com.monban.privileged"
      delete:
        - /usr/local/bin/monban-pam-helper
        - /usr/local/lib/pam/pam_monban.so
        - /Library/Security/SecurityAgentPlugins/monban-auth.bundle
        - /usr/local/libexec/monban-privileged
        - /Library/LaunchDaemons/com.monban.privileged.plist
    zap:
      trash:
        - ~/.config/monban
```

Verify after first CI run: GoReleaser picks the correct cask artifact type (`pkg` stanza, not `app`) given the `.pkg` URL. If it emits `app`, switch to an explicit `custom_block` with a `pkg "Monban-#{version}.pkg"` line.

### CI changes

In `.github/workflows/release.yml`, `build-darwin` job:
- Replace `args: build --clean -f .goreleaser-darwin.yml` with `args: release --clean -f .goreleaser-darwin.yml`.
- Remove the separate `gh release create` step in the `release` job for darwin artifacts (GoReleaser now owns it). Linux release steps stay.
- Pass `HOMEBREW_TAP_TOKEN`: `env: { HOMEBREW_TAP_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }} }`.

### Phase 3 acceptance

- [ ] Tag a release → CI publishes `.pkg` to GitHub releases.
- [ ] CI pushes an updated `Casks/monban.rb` to the tap repo with the correct SHA-256.
- [ ] Fresh macOS VM: `brew tap flythenimbus/tap && brew install --cask monban` installs cleanly with no Gatekeeper friction (brew strips quarantine).
- [ ] `brew upgrade --cask monban` after the next release picks up the new version.
- [ ] `brew uninstall --cask monban` removes all installed files (verify all paths in `uninstall.delete:` and the LaunchDaemon is booted out).
- [ ] `brew uninstall --cask --zap monban` additionally removes `~/.config/monban`.

### Phase 3 risks / things to verify in review

- GoReleaser's `homebrew_casks` is free-tier but evolves across v2 minor versions. If the emitted cask doesn't have a `pkg` stanza, the cask installs the `.pkg` as an opaque blob and postinstall scripts don't run — breaking everything.
- The `uninstall.pkgutil` id must exactly match the `--identifier` passed to `pkgbuild` in Phase 1 (`com.monban.pkg`).
- Codeberg release mirror: current workflow mirrors GitHub releases to Codeberg. Verify the darwin GoReleaser release doesn't interfere (it should only write to GitHub; the mirror step runs after).

---

## Sequencing

1. **Phase 1 PR** — `.pkg` build + CI upload only. Review on: Taskfile correctness, distribution.xml minimal but valid, postinstall doesn't touch PAM files, CI produces artifact.
2. **Phase 2 PR** — daemon + client + protocol + postinstall bootstrapping. Review on: challenge/response correctness, assertion binding to challenge, atomic PAM-file writes, osascript fallback preserved, lockout mitigations.
3. **Phase 3 PR** — GoReleaser cask + tap repo wiring. Review on: cask URL/SHA resolution, uninstall list completeness, switch from `build` to `release`.

Tag a release between each phase so the Homebrew tap ends up pinned to a known-working binary even if a later phase is in flight.

---

## Phase 2.5 — Pivot: delete the daemon, configure at install time (supersedes Phase 2)

### Why this exists

macOS Tahoe (26.x) hardened `/etc/pam.d/` against writes from non-sanctioned root processes. Our unsigned LaunchDaemon, running under launchd's system domain, gets EPERM on every attempt — even as root. Verified: a manual `sudo sh -c 'echo ... > /etc/pam.d/sudo_local'` from a user shell succeeds, and a diagnostic `echo` in the pkg postinstall also succeeds; only the daemon is blocked. Apple's entitlement model treats Installer.app as special; daemons are not.

Rather than add Developer ID signing + entitlements (explicitly rejected by the project's "minimize Apple dependency" stance), we pivot: everything the daemon did at toggle time is now done once, at pkg install time, inside the Installer-privileged postinstall context.

### New contract

- Installing the `.pkg` = admin_gate is **always on**. YubiKey is required for `sudo` and for native admin dialogs.
- No runtime off / default / strict toggle. Mode is fixed at `sufficient` (YubiKey success grants, failure falls through to password) — see `postinstall` for the exact PAM line.
- "Turn admin_gate off" = uninstall the pkg.

### What changed vs Phase 2

**Deleted:**
- `desktop/cmd/monban-privileged/` (whole LaunchDaemon package)
- `desktop/internal/monban/privileged.go`, `privileged_client.go`, `privileged_server.go`
- `desktop/internal/monban/admin_gate_darwin.go`, `admin_gate_other.go`
- `desktop/build/darwin/com.monban.privileged.plist`
- `build:privileged` Taskfile entry
- Daemon copy + plist copy in `create:app:bundle` / `run` tasks
- Daemon deploy + `launchctl bootstrap` + `kickstart` in postinstall
- `launchctl bootout` in preinstall
- Pre-Phase-2 dead code (`InstallSudoGate`, `RemoveSudoGate`, `BatchPrivilegedWrites`, `RunWithPrivileges`, `writeFilePrivileged`, `PrivilegedWrite`, `IsPamInstalled`, `BuildPamContent`, `buildPamContentForPath`, `shellQuote`, `writeTempFile`) that was never actually called
- `SecureConfig.AdminGate` field. Breaking change: no migration path. Pre-2.5 configs fail HMAC verification on first unlock (since the payload format changed) and are treated as tampered. Existing users must delete `~/.config/monban/credentials.json` and re-register, which **permanently loses access to any pre-2.5 vaults** (new master secret is generated on re-register).
- `CombinedSettings.AdminGate` frontend-facing field
- Frontend `GateMode` type, `admin_gate` entry in `AdminContext`, the entire admin-gate `<Select>` block in `GeneralTab.tsx`
- `TestNormalizeGateMode`, old `TestVerifySecureConfigDetectsAdminGateTampering` and related assertions

**Added / changed:**
- `desktop/build/darwin/pkg/scripts/postinstall` now:
  - Writes `/etc/pam.d/sudo_local` with `auth sufficient /usr/local/lib/pam/pam_monban.so # monban sudo gate` (mode 0444)
  - Backs up the current `system.preferences` and `system.preferences.security` authorizationdb rights to `/Library/Security/SecurityAgentPlugins/<right>.monban-backup` (only if backup doesn't already exist)
  - Rewrites both rights to `class: evaluate-mechanisms` pointing at `monban-auth:auth`
- `welcome.html` updated to disclose what the installer is about to change
- `desktop/scripts/test_install.sh` now verifies PAM + authorizationdb state instead of daemon state; also asserts that no stale daemon artefacts exist

### Phase 2.5 acceptance

- [ ] `desktop/scripts/test_install.sh` exits 0 after `sudo installer -pkg bin/Monban-*.pkg -target /`
- [ ] `/etc/pam.d/sudo_local` exists with the monban tag, owned root:wheel, mode 0444
- [ ] `security authorizationdb read system.preferences` shows `class: evaluate-mechanisms` and mechanism `monban-auth:auth`
- [ ] `.monban-backup` files exist for both rebound rights
- [ ] `sudo -k && sudo true` in Terminal prompts for YubiKey PIN, not macOS password
- [ ] System Settings → toggling a protected pane prompts for YubiKey
- [ ] `launchctl list | grep monban` returns nothing
- [ ] `pkgutil --pkgs | grep monban` shows only `com.monban.pkg`
- [ ] `task test`, `go vet ./...`, `bun x tsc --noEmit` all clean

### Phase 2.5 risks / things to verify in review

- **Lockout risk** on a broken `pam_monban.so` install: `sufficient` means sudo falls through to the password prompt on helper failure, so the worst-case scenario is "admin_gate silently no-ops" rather than "nobody can sudo". Upgrading to `auth_err=die` for true no-fallback strict is a future option.
- **`admin_gate` field removal is a clean break with no migration path.** Pre-2.5 configs will fail HMAC verification and show as tampered; users must delete `~/.config/monban/credentials.json` and re-register, which permanently loses access to any pre-2.5 vaults. Acceptable because Monban is pre-1.0 OSS and the HMAC format has never been stable; documented prominently in the README.
- **Linux admin_gate is temporarily broken** (no more `getAdminGateCommand` terminal flow; no Linux equivalent of the pkg postinstall). Tracked as out-of-scope here; needs a dedicated Linux phase that writes `/etc/pam.d/sudo` from the `.deb`/`.rpm` postinst.
