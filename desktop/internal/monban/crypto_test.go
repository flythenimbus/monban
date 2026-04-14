package monban

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	plaintext := []byte("hello world, this is a test file!")

	dir := t.TempDir()
	src := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.enc")
	dec := filepath.Join(dir, "plain.dec.txt")

	_ = os.WriteFile(src, plaintext, 0600)

	if err := EncryptFile(key, src, enc); err != nil {
		t.Fatal(err)
	}

	// Encrypted file should differ from plaintext
	encData, _ := os.ReadFile(enc)
	if bytes.Equal(encData, plaintext) {
		t.Error("encrypted file should not equal plaintext")
	}

	if err := DecryptFile(key, enc, dec); err != nil {
		t.Fatal(err)
	}

	result, _ := os.ReadFile(dec)
	if !bytes.Equal(plaintext, result) {
		t.Error("decrypted content does not match original")
	}
}

func TestEncryptDecryptLargeFile(t *testing.T) {
	key := bytes.Repeat([]byte{0xCD}, 32)

	// 200KB = ~3 chunks
	plaintext := make([]byte, 200*1024)
	rand.Read(plaintext)

	dir := t.TempDir()
	src := filepath.Join(dir, "large.bin")
	enc := filepath.Join(dir, "large.bin.enc")
	dec := filepath.Join(dir, "large.dec.bin")

	_ = os.WriteFile(src, plaintext, 0600)

	if err := EncryptFile(key, src, enc); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(key, enc, dec); err != nil {
		t.Fatal(err)
	}

	result, _ := os.ReadFile(dec)
	if !bytes.Equal(plaintext, result) {
		t.Error("decrypted large file does not match original")
	}
}

func TestEncryptDecryptEmptyFile(t *testing.T) {
	key := bytes.Repeat([]byte{0xEF}, 32)

	dir := t.TempDir()
	src := filepath.Join(dir, "empty.txt")
	enc := filepath.Join(dir, "empty.txt.enc")
	dec := filepath.Join(dir, "empty.dec.txt")

	_ = os.WriteFile(src, []byte{}, 0600)

	if err := EncryptFile(key, src, enc); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(key, enc, dec); err != nil {
		t.Fatal(err)
	}

	result, _ := os.ReadFile(dec)
	if len(result) != 0 {
		t.Errorf("expected empty file, got %d bytes", len(result))
	}
}

func TestEncryptDecryptExactChunkSize(t *testing.T) {
	key := bytes.Repeat([]byte{0x12}, 32)

	plaintext := make([]byte, ChunkSize)
	rand.Read(plaintext)

	dir := t.TempDir()
	src := filepath.Join(dir, "exact.bin")
	enc := filepath.Join(dir, "exact.bin.enc")
	dec := filepath.Join(dir, "exact.dec.bin")

	_ = os.WriteFile(src, plaintext, 0600)

	if err := EncryptFile(key, src, enc); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(key, enc, dec); err != nil {
		t.Fatal(err)
	}

	result, _ := os.ReadFile(dec)
	if !bytes.Equal(plaintext, result) {
		t.Error("exact chunk-size file round-trip failed")
	}
}

func TestDecryptCorruptedFile(t *testing.T) {
	key := bytes.Repeat([]byte{0x34}, 32)
	plaintext := []byte("important data")

	dir := t.TempDir()
	src := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.enc")
	dec := filepath.Join(dir, "plain.dec.txt")

	_ = os.WriteFile(src, plaintext, 0600)
	_ = EncryptFile(key, src, enc)

	// Corrupt the encrypted file
	data, _ := os.ReadFile(enc)
	data[len(data)-1] ^= 0xFF
	_ = os.WriteFile(enc, data, 0600)

	err := DecryptFile(key, enc, dec)
	if err == nil {
		t.Error("decrypting corrupted file should fail")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := bytes.Repeat([]byte{0x56}, 32)
	key2 := bytes.Repeat([]byte{0x78}, 32)
	plaintext := []byte("secret stuff")

	dir := t.TempDir()
	src := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.enc")
	dec := filepath.Join(dir, "plain.dec.txt")

	_ = os.WriteFile(src, plaintext, 0600)
	_ = EncryptFile(key1, src, enc)

	err := DecryptFile(key2, enc, dec)
	if err == nil {
		t.Error("decrypting with wrong key should fail")
	}
}

func TestEncryptDecryptMultipleChunks(t *testing.T) {
	key := bytes.Repeat([]byte{0x9A}, 32)

	// 3.5 chunks worth of data
	plaintext := make([]byte, ChunkSize*3+ChunkSize/2)
	rand.Read(plaintext)

	dir := t.TempDir()
	src := filepath.Join(dir, "multi.bin")
	enc := filepath.Join(dir, "multi.bin.enc")
	dec := filepath.Join(dir, "multi.dec.bin")

	_ = os.WriteFile(src, plaintext, 0600)

	_ = EncryptFile(key, src, enc)
	_ = DecryptFile(key, enc, dec)

	result, _ := os.ReadFile(dec)
	if !bytes.Equal(plaintext, result) {
		t.Error("multi-chunk round-trip failed")
	}
}

func TestEncryptedFileLargerThanPlaintext(t *testing.T) {
	key := bytes.Repeat([]byte{0xBC}, 32)
	plaintext := []byte("small")

	dir := t.TempDir()
	src := filepath.Join(dir, "small.txt")
	enc := filepath.Join(dir, "small.txt.enc")

	_ = os.WriteFile(src, plaintext, 0600)
	_ = EncryptFile(key, src, enc)

	srcInfo, _ := os.Stat(src)
	encInfo, _ := os.Stat(enc)

	if encInfo.Size() <= srcInfo.Size() {
		t.Error("encrypted file should be larger (header + GCM tag overhead)")
	}
}

func TestDecryptTruncatedFile(t *testing.T) {
	key := bytes.Repeat([]byte{0xDE}, 32)

	dir := t.TempDir()
	dec := filepath.Join(dir, "out.txt")

	// File too short to even have a header
	short := filepath.Join(dir, "short.enc")
	_ = os.WriteFile(short, []byte{1, 2, 3}, 0600)

	err := DecryptFile(key, short, dec)
	if err == nil {
		t.Error("truncated file should fail decryption")
	}
}

func TestDeriveChunkNonceUniqueness(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xAA}, 12)

	seen := make(map[string]bool)
	for i := uint64(0); i < 100; i++ {
		cn := deriveChunkNonce(nonce, i)
		key := string(cn)
		if seen[key] {
			t.Errorf("chunk nonce collision at index %d", i)
		}
		seen[key] = true
	}
}

func TestDeriveChunkNonceDoesNotMutateOriginal(t *testing.T) {
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	original := make([]byte, len(nonce))
	copy(original, nonce)

	deriveChunkNonce(nonce, 42)

	if !bytes.Equal(nonce, original) {
		t.Error("deriveChunkNonce should not mutate the original nonce")
	}
}

func TestDecryptDetectsTamperedHeader(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	plaintext := []byte("authenticated header test")

	dir := t.TempDir()
	src := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.enc")
	dec := filepath.Join(dir, "plain.dec.txt")

	_ = os.WriteFile(src, plaintext, 0600)
	_ = EncryptFile(key, src, enc)

	// Tamper with the chunk size field in the header (bytes 12-15)
	data, _ := os.ReadFile(enc)
	data[14] ^= 0xFF // flip a byte in chunk size
	_ = os.WriteFile(enc, data, 0600)

	err := DecryptFile(key, enc, dec)
	if err == nil {
		t.Error("decryption should fail when header is tampered (AAD mismatch)")
	}
}

func TestDecryptDetectsTamperedNonce(t *testing.T) {
	key := bytes.Repeat([]byte{0xCD}, 32)
	plaintext := []byte("nonce tamper test data")

	dir := t.TempDir()
	src := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.enc")
	dec := filepath.Join(dir, "plain.dec.txt")

	_ = os.WriteFile(src, plaintext, 0600)
	_ = EncryptFile(key, src, enc)

	// Tamper with the nonce in the header (first 12 bytes)
	data, _ := os.ReadFile(enc)
	data[0] ^= 0xFF
	_ = os.WriteFile(enc, data, 0600)

	err := DecryptFile(key, enc, dec)
	if err == nil {
		t.Error("decryption should fail when nonce is tampered")
	}
}

func TestHeaderSwapBetweenFiles(t *testing.T) {
	key := bytes.Repeat([]byte{0xEF}, 32)

	dir := t.TempDir()
	src1 := filepath.Join(dir, "file1.txt")
	src2 := filepath.Join(dir, "file2.txt")
	enc1 := filepath.Join(dir, "file1.enc")
	enc2 := filepath.Join(dir, "file2.enc")
	dec := filepath.Join(dir, "dec.txt")

	_ = os.WriteFile(src1, []byte("content of file 1"), 0600)
	_ = os.WriteFile(src2, []byte("content of file 2"), 0600)
	_ = EncryptFile(key, src1, enc1)
	_ = EncryptFile(key, src2, enc2)

	// Swap headers: put file2's header on file1's body
	data1, _ := os.ReadFile(enc1)
	data2, _ := os.ReadFile(enc2)
	swapped := append(data2[:FileHeaderSize], data1[FileHeaderSize:]...)
	swappedPath := filepath.Join(dir, "swapped.enc")
	_ = os.WriteFile(swappedPath, swapped, 0600)

	err := DecryptFile(key, swappedPath, dec)
	if err == nil {
		t.Error("decryption should fail when headers are swapped between files (AAD mismatch)")
	}
}
