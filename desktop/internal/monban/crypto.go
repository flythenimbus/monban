package monban

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	// ChunkSize is the plaintext size per encryption chunk.
	ChunkSize = 64 * 1024 // 64 KB
	// FileHeaderSize is nonce (12) + chunk size (4).
	FileHeaderSize = 16
)

// EncryptFile encrypts srcPath to dstPath using AES-256-GCM in streaming chunks.
// Format: [12-byte file nonce] [4-byte chunk size (big endian)] [chunk1] [chunk2] ...
// Each chunk: [ciphertext + 16-byte GCM tag]
// Chunk nonce is derived: fileNonce XOR chunkIndex (as 12-byte big endian).
func EncryptFile(key []byte, srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating destination: %w", err)
	}
	defer dst.Close()

	gcm, err := newGCM(key)
	if err != nil {
		return err
	}

	// Generate file nonce
	fileNonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(fileNonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	// Write header: nonce + chunk size
	header := make([]byte, FileHeaderSize)
	copy(header, fileNonce)
	binary.BigEndian.PutUint32(header[12:], ChunkSize)
	if _, err := dst.Write(header); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	buf := make([]byte, ChunkSize)
	chunkIdx := uint64(0)

	for {
		n, readErr := io.ReadFull(src, buf)
		if n > 0 {
			chunkNonce := deriveChunkNonce(fileNonce, chunkIdx)
			encrypted := gcm.Seal(nil, chunkNonce, buf[:n], nil)
			if _, err := dst.Write(encrypted); err != nil {
				return fmt.Errorf("writing chunk %d: %w", chunkIdx, err)
			}
			chunkIdx++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("reading chunk %d: %w", chunkIdx, readErr)
		}
	}

	if err := dst.Sync(); err != nil {
		return fmt.Errorf("syncing: %w", err)
	}

	return nil
}

// DecryptFile decrypts srcPath to dstPath using AES-256-GCM in streaming chunks.
func DecryptFile(key []byte, srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating destination: %w", err)
	}
	defer dst.Close()

	gcm, err := newGCM(key)
	if err != nil {
		return err
	}

	// Read header
	header := make([]byte, FileHeaderSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return fmt.Errorf("reading header: %w", err)
	}

	fileNonce := header[:12]
	chunkSize := binary.BigEndian.Uint32(header[12:])

	// Each encrypted chunk is chunkSize + GCM overhead
	encChunkSize := int(chunkSize) + gcm.Overhead()
	buf := make([]byte, encChunkSize)
	chunkIdx := uint64(0)

	for {
		n, readErr := io.ReadFull(src, buf)
		if n > 0 {
			chunkNonce := deriveChunkNonce(fileNonce, chunkIdx)
			plaintext, err := gcm.Open(nil, chunkNonce, buf[:n], nil)
			if err != nil {
				return fmt.Errorf("decrypting chunk %d: %w", chunkIdx, err)
			}
			if _, err := dst.Write(plaintext); err != nil {
				return fmt.Errorf("writing chunk %d: %w", chunkIdx, err)
			}
			chunkIdx++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("reading chunk %d: %w", chunkIdx, readErr)
		}
	}

	if err := dst.Sync(); err != nil {
		return fmt.Errorf("syncing: %w", err)
	}

	return nil
}

// deriveChunkNonce XORs the file nonce with the chunk index to produce a unique
// nonce per chunk without requiring additional random bytes.
func deriveChunkNonce(fileNonce []byte, chunkIdx uint64) []byte {
	nonce := make([]byte, len(fileNonce))
	copy(nonce, fileNonce)
	// XOR the last 8 bytes with the chunk index
	idxBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(idxBytes, chunkIdx)
	for i := range 8 {
		nonce[len(nonce)-8+i] ^= idxBytes[i]
	}
	return nonce
}
