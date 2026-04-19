# Monban Desktop

Desktop app built with Wails v3, React 18, and Tailwind CSS v4.

## Prerequisites

A YubiKey with FIDO2 support is required at runtime.

**macOS:**
```bash
brew install libfido2
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install libfido2-dev libgtk-3-dev libwebkit2gtk-4.1-dev
```

**Linux (Fedora):**
```bash
sudo dnf install libfido2-devel gtk3-devel webkit2gtk4.1-devel
```

## Development

```bash
cd frontend && bun install && cd ..
task dev
```

## Build

```bash
task package        # macOS: builds Monban.app + Monban-<version>.pkg
task linux:package  # Linux: deb/rpm/AppImage
```

## Test

```bash
task test
```

## Install

### macOS

Install the `.pkg` from `bin/`:

```bash
sudo installer -pkg bin/Monban-*.pkg -target /
```

Installing the pkg **immediately gates `sudo` and native admin authorization
dialogs** (System Settings, Installer, etc.) behind your registered YubiKey.
There is no runtime toggle — installing is the opt-in; uninstalling is the
opt-out. Original `authorizationdb` rights are backed up to
`/Library/Security/SecurityAgentPlugins/*.monban-backup` so uninstall can
restore them.

After install, run `desktop/scripts/test_install.sh` to verify the pkg placed
everything correctly.

### Linux

Install the `.deb` or `.rpm` from `bin/`, or run the AppImage directly. Auto-start is managed via Settings. Note: Linux admin_gate UX is currently unavailable — tracked as a separate phase.

## Uninstall

Unlock and remove all protected items first, then:

**macOS:**
```bash
# Stop the app and forget the pkg registration.
pkill -x Monban 2>/dev/null || true
sudo pkgutil --forget com.monban.pkg

# Restore every authorizationdb right we rebound.
for backup in /Library/Security/SecurityAgentPlugins/*.monban-backup; do
    [ -f "$backup" ] || continue
    right=$(basename "$backup" .monban-backup)
    sudo security authorizationdb write "$right" < "$backup"
    sudo rm -f "$backup"
done

# Remove installed system files.
sudo rm -f /etc/pam.d/sudo_local \
          /usr/local/bin/monban-pam-helper \
          /usr/local/lib/pam/pam_monban.so
sudo rm -rf /Library/Security/SecurityAgentPlugins/monban-auth.bundle
sudo rm -rf /Applications/Monban.app

# Remove autostart + user config.
launchctl unload ~/Library/LaunchAgents/com.monban.agent.plist 2>/dev/null || true
rm -f ~/Library/LaunchAgents/com.monban.agent.plist
rm -rf ~/.config/monban
```

**Linux:**
```bash
rm ~/.config/autostart/monban.desktop
rm -rf ~/.config/monban
```

