package plugin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Installer installs plugins from a catalog by downloading + verifying
// the signed manifest and tarball, extracting the tarball into
// PluginsDir/<name>/, and writing the manifest alongside.
type Installer struct {
	PluginsDir string
	HTTPClient *http.Client
	// RunInstallPkg runs a macOS .pkg as root. Injectable so tests can
	// assert we invoke it without actually running anything system-wide.
	// Defaults to runInstallPkgViaOsascript.
	RunInstallPkg func(ctx context.Context, pkgPath string) error
}

// NewInstaller returns an Installer with sensible defaults. Pass an
// explicit client for tests.
func NewInstaller(pluginsDir string) *Installer {
	return &Installer{
		PluginsDir:    pluginsDir,
		HTTPClient:    &http.Client{Timeout: 60 * time.Second},
		RunInstallPkg: runInstallPkgViaOsascript,
	}
}

const maxDownloadBytes = 50 * 1024 * 1024 // 50 MiB

// Install downloads, verifies, and extracts the plugin described by e.
// Returns the directory name under PluginsDir that was written (equal
// to the manifest's declared name).
func (i *Installer) Install(ctx context.Context, e *CatalogEntry) (string, error) {
	platform := CurrentPlatform()
	if !e.SupportsPlatform(platform) {
		return "", fmt.Errorf("plugin %s does not support %s", e.Name, platform)
	}

	manifestURL, manifestSigURL, tarballURL, tarballSigURL := e.ResolvedURLs(platform)

	manifestBytes, err := i.fetch(ctx, manifestURL)
	if err != nil {
		return "", fmt.Errorf("download manifest: %w", err)
	}
	manifestSig, err := i.fetch(ctx, manifestSigURL)
	if err != nil {
		return "", fmt.Errorf("download manifest sig: %w", err)
	}
	if err := Verify(manifestBytes, manifestSig); err != nil {
		return "", fmt.Errorf("verify manifest: %w", err)
	}

	m, err := ParseManifest(manifestBytes)
	if err != nil {
		return "", fmt.Errorf("parse manifest: %w", err)
	}
	if m.Name != e.Name {
		return "", fmt.Errorf("manifest name %q does not match catalog entry %q", m.Name, e.Name)
	}
	if ok, reason := m.IsCompatibleAPI(); !ok {
		return "", fmt.Errorf("plugin API incompatible: %s", reason)
	}

	tarballBytes, err := i.fetch(ctx, tarballURL)
	if err != nil {
		return "", fmt.Errorf("download tarball: %w", err)
	}
	tarballSig, err := i.fetch(ctx, tarballSigURL)
	if err != nil {
		return "", fmt.Errorf("download tarball sig: %w", err)
	}
	if err := Verify(tarballBytes, tarballSig); err != nil {
		return "", fmt.Errorf("verify tarball: %w", err)
	}

	// Stage extraction in a temp dir inside PluginsDir, then rename into
	// place. Keeps a half-extracted payload from ever being visible to
	// the host's loadOne() scan.
	if err := os.MkdirAll(i.PluginsDir, 0755); err != nil {
		return "", fmt.Errorf("ensure plugins dir: %w", err)
	}
	staging, err := os.MkdirTemp(i.PluginsDir, ".install-"+m.Name+"-")
	if err != nil {
		return "", fmt.Errorf("create staging dir: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(staging)
		}
	}()

	if err := extractTarGz(tarballBytes, staging); err != nil {
		return "", fmt.Errorf("extract tarball: %w", err)
	}

	// Drop manifest + sig next to the extracted payload.
	if err := os.WriteFile(filepath.Join(staging, "manifest.json"), manifestBytes, 0644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(staging, "manifest.json.sig"), manifestSig, 0644); err != nil {
		return "", err
	}

	// Atomic move into place. If a previous install exists, remove first —
	// upgrades overwrite.
	final := filepath.Join(i.PluginsDir, m.Name)
	if err := os.RemoveAll(final); err != nil {
		return "", fmt.Errorf("remove previous install: %w", err)
	}
	if err := os.Rename(staging, final); err != nil {
		return "", fmt.Errorf("commit install: %w", err)
	}
	cleanup = false

	// Post-extract hook: run the manifest-declared installer .pkg if any.
	// The admin-gate plugin uses this to write /etc/pam.d/ entries and
	// rebind authorizationdb — operations that need root and are
	// expected to trigger a standard macOS admin password prompt.
	if m.InstallPkg != "" {
		pkgPath := filepath.Join(final, m.InstallPkg)
		if _, err := os.Stat(pkgPath); err != nil {
			return "", fmt.Errorf("declared install_pkg %q not in payload: %w", m.InstallPkg, err)
		}
		if i.RunInstallPkg == nil {
			return "", fmt.Errorf("plugin requires install_pkg but host has no runner")
		}
		if err := i.RunInstallPkg(ctx, pkgPath); err != nil {
			return "", fmt.Errorf("run install_pkg: %w", err)
		}
	}

	return m.Name, nil
}

// runInstallPkgViaOsascript invokes /usr/sbin/installer via AppleScript's
// `do shell script ... with administrator privileges`, which triggers
// the standard macOS admin-password prompt. This is the Apple-free
// install path: the tarball is already ed25519-verified, so Gatekeeper
// isn't the trust boundary — the signed tarball is.
func runInstallPkgViaOsascript(ctx context.Context, pkgPath string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("install_pkg is macOS-only (got %s)", runtime.GOOS)
	}
	// AppleScript's `quoted form of` handles shell quoting for us, but
	// we still have to AppleScript-escape the path before splicing into
	// the script source.
	safe := strings.ReplaceAll(pkgPath, `\`, `\\`)
	safe = strings.ReplaceAll(safe, `"`, `\"`)
	script := fmt.Sprintf(
		`do shell script "/usr/sbin/installer -pkg " & quoted form of "%s" & " -target /" with administrator privileges`,
		safe,
	)
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("installer: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// fetch performs an HTTP GET with a size cap and returns the body bytes.
func (i *Installer) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := i.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes+1))
}

// extractTarGz extracts a gzipped tar archive into dstDir. Guards against
// path traversal (entries with `..`) and symlinks that escape dstDir.
func extractTarGz(data []byte, dstDir string) error {
	absDst, err := filepath.Abs(dstDir)
	if err != nil {
		return err
	}

	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		name := filepath.Clean(hdr.Name)
		if strings.HasPrefix(name, "..") || strings.Contains(name, string(filepath.Separator)+"..") {
			return fmt.Errorf("tar: illegal path %q", hdr.Name)
		}
		target := filepath.Join(absDst, name)
		rel, err := filepath.Rel(absDst, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("tar: path escapes staging %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode & 0777)
			if mode == 0 {
				mode = 0644
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, maxDownloadBytes)); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("tar: symlink/hardlink entries not allowed (%q)", hdr.Name)
		default:
			// Ignore unknown types — e.g. xattr/PAX headers.
		}
	}
}
