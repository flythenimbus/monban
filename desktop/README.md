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
task package        # macOS: builds Monban.app
task linux:package  # Linux: deb/rpm/AppImage
```

## Test

```bash
task test
```

## Install

### macOS

Move `Monban.app` from `bin/` (or the release zip) to `/Applications`:

```bash
mv bin/Monban.app /Applications/
```

Monban installs its own LaunchAgent on first run.

### Linux

Install the `.deb` or `.rpm` from `bin/`, or run the AppImage directly.
Auto-start is managed via Settings.

## Uninstall

Unlock and remove all protected items first, then:

**macOS:**
```bash
pkill -x Monban 2>/dev/null || true
sudo rm -rf /Applications/Monban.app
launchctl unload ~/Library/LaunchAgents/com.monban.agent.plist 2>/dev/null || true
rm -f ~/Library/LaunchAgents/com.monban.agent.plist
rm -rf ~/.config/monban
```

**Linux:**
```bash
rm ~/.config/autostart/monban.desktop
rm -rf ~/.config/monban
```
