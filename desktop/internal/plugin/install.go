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
	"path/filepath"
	"strings"
	"time"
)

// Installer installs plugins from a catalog by downloading + verifying
// the signed manifest and tarball, extracting the tarball into
// PluginsDir/<name>/, and writing the manifest alongside.
type Installer struct {
	PluginsDir string
	HTTPClient *http.Client
}

// NewInstaller returns an Installer with sensible defaults. Pass an
// explicit client for tests.
func NewInstaller(pluginsDir string) *Installer {
	return &Installer{
		PluginsDir: pluginsDir,
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
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
	return m.Name, nil
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
