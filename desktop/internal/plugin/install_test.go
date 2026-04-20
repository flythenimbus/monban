package plugin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTarGz produces a gzipped tar with the given path→content entries.
func buildTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0755,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractTarGzRejectsPathTraversal(t *testing.T) {
	tarball := buildTarGz(t, map[string][]byte{
		"../../etc/passwd": []byte("evil"),
	})
	dir := t.TempDir()
	err := extractTarGz(tarball, dir)
	if err == nil {
		t.Fatal("expected path traversal rejection")
	}
	if !strings.Contains(err.Error(), "illegal path") && !strings.Contains(err.Error(), "escapes") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtractTarGzRejectsSymlink(t *testing.T) {
	// Hand-craft a tar with a symlink entry.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	_ = tw.Close()
	_ = gz.Close()

	dir := t.TempDir()
	err := extractTarGz(buf.Bytes(), dir)
	if err == nil {
		t.Fatal("symlink entries must be rejected")
	}
}

func TestInstallerRoundTripWithMockServer(t *testing.T) {
	priv := withTempKey(t)

	// Build a manifest that matches the embedded hello-world plugin shape.
	m := map[string]any{
		"name":       "hello-world",
		"version":    "0.1.0",
		"monban_api": HostAPIVersion,
		"platforms":  []string{CurrentPlatform()},
		"kind":       []string{"observer"},
		"hooks":      []string{"on:app_started"},
		"binary":     map[string]string{CurrentPlatform(): "bin/hello-world"},
	}
	manifestBytes, _ := json.MarshalIndent(m, "", "  ")
	manifestSig := ed25519.Sign(priv, manifestBytes)

	// Minimal tarball: one file under bin/.
	tarball := buildTarGz(t, map[string][]byte{
		"bin/hello-world": []byte("#!/bin/sh\necho hi\n"),
	})
	tarballSig := ed25519.Sign(priv, tarball)

	// Mock release server.
	mux := http.NewServeMux()
	mux.HandleFunc("/hello-world-0.1.0-manifest.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(manifestBytes)
	})
	mux.HandleFunc("/hello-world-0.1.0-manifest.json.sig", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(manifestSig)
	})
	mux.HandleFunc(fmt.Sprintf("/hello-world-0.1.0-%s.tar.gz", CurrentPlatform()), func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarball)
	})
	mux.HandleFunc(fmt.Sprintf("/hello-world-0.1.0-%s.tar.gz.sig", CurrentPlatform()), func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarballSig)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	entry := &CatalogEntry{
		Name:           "hello-world",
		Version:        "0.1.0",
		Platforms:      []string{CurrentPlatform()},
		ManifestURL:    srv.URL + "/hello-world-{version}-manifest.json",
		ManifestSigURL: srv.URL + "/hello-world-{version}-manifest.json.sig",
		TarballURL:     srv.URL + "/hello-world-{version}-{platform}.tar.gz",
		TarballSigURL:  srv.URL + "/hello-world-{version}-{platform}.tar.gz.sig",
	}

	pluginsDir := t.TempDir()
	inst := NewInstaller(pluginsDir)
	ctx := context.Background()
	name, err := inst.Install(ctx, entry)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if name != "hello-world" {
		t.Errorf("Install returned name %q, want hello-world", name)
	}

	// Verify final layout: manifest + sig + binary.
	pluginDir := filepath.Join(pluginsDir, "hello-world")
	for _, f := range []string{"manifest.json", "manifest.json.sig", "bin/hello-world"} {
		if _, err := os.Stat(filepath.Join(pluginDir, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
}

func TestInstallerRejectsTamperedManifest(t *testing.T) {
	priv := withTempKey(t)

	manifestBytes := []byte(`{"name":"x","version":"1","monban_api":"0.1","platforms":["linux-amd64"],"kind":["observer"],"binary":{"linux-amd64":"bin/x"}}`)
	goodSig := ed25519.Sign(priv, manifestBytes)
	tarball := buildTarGz(t, map[string][]byte{"bin/x": []byte("x")})
	tarballSig := ed25519.Sign(priv, tarball)

	// Serve a tampered manifest but the ORIGINAL signature — should fail verify.
	tampered := bytes.Replace(manifestBytes, []byte(`"x"`), []byte(`"evil"`), 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/m", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(tampered) })
	mux.HandleFunc("/ms", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(goodSig) })
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(tarball) })
	mux.HandleFunc("/ts", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(tarballSig) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	entry := &CatalogEntry{
		Name:           "x",
		Version:        "1",
		Platforms:      []string{CurrentPlatform()},
		ManifestURL:    srv.URL + "/m",
		ManifestSigURL: srv.URL + "/ms",
		TarballURL:     srv.URL + "/t",
		TarballSigURL:  srv.URL + "/ts",
	}

	// Test only runs meaningfully on a platform the manifest declares;
	// otherwise Install returns a platform-mismatch error before the sig
	// check. Skip if we can't exercise the verify path.
	if CurrentPlatform() != "linux-amd64" {
		t.Skip("manifest declares linux-amd64 only; skipping on " + CurrentPlatform())
	}

	inst := NewInstaller(t.TempDir())
	_, err := inst.Install(context.Background(), entry)
	if err == nil || !strings.Contains(err.Error(), "verify manifest") {
		t.Fatalf("expected manifest verify failure, got %v", err)
	}
}

func TestCatalogRoundTrip(t *testing.T) {
	c, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if c.Schema != 1 {
		t.Errorf("schema = %d, want 1", c.Schema)
	}
	if len(c.Plugins) == 0 {
		t.Fatal("embedded catalog should not be empty")
	}
}

func TestCatalogEntryExpand(t *testing.T) {
	e := &CatalogEntry{
		Version:     "0.1.0",
		TarballURL:  "https://example.com/x-{version}-{platform}.tar.gz",
		ManifestURL: "https://example.com/x-{version}-manifest.json",
	}
	_, _, tarball, _ := e.ResolvedURLs("darwin-arm64")
	want := "https://example.com/x-0.1.0-darwin-arm64.tar.gz"
	if tarball != want {
		t.Errorf("tarball URL = %q, want %q", tarball, want)
	}
}
