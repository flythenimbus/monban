package monban

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	// ChunkSize is the plaintext size per encryption chunk.
	// 1 MB chunks ~16x reduce GCM Seal/Open call overhead vs 64 KB
	// while still bounded enough to stream without blowing memory.
	// Old vaults with 64 KB chunks decrypt fine — chunk size is read
	// from the header.
	ChunkSize = 1024 * 1024 // 1 MB

	// FileHeaderSize is the on-disk header: magic (4) + nonce (12) +
	// chunk size (4). Per-chunk AAD carries a final-flag byte so the
	// decrypter detects tail truncation.
	FileHeaderSize = 20

	// ioBufferSize sizes the bufio reader/writer wrappers around the
	// source/destination files. One chunk's worth means bufio
	// coalesces the per-chunk Write/Read into one syscall.
	ioBufferSize = ChunkSize + 16
)

// fileMagic is the 4-byte marker at the start of every ciphertext.
// Present so a future format change can be switched on cleanly.
var fileMagic = [4]byte{'M', 'B', 0x02, 0x01}

// chunkFlagNonFinal / chunkFlagFinal are the single-byte AAD markers
// that distinguish intermediate chunks from the tail chunk. The tag
// of a chunk encrypted with flag=0x00 cannot be verified against AAD
// with flag=0x01, so an attacker who drops the real tail cannot
// re-mark the new last chunk as final.
const (
	chunkFlagNonFinal byte = 0x00
	chunkFlagFinal    byte = 0x01
)

// ErrTruncatedCiphertext is returned when a ciphertext ends without a
// final-flagged chunk. This is how tail-truncation attacks surface
// to the caller.
var ErrTruncatedCiphertext = errors.New("ciphertext truncated: no final chunk")

// EncryptFile encrypts srcPath to dstPath using AES-256-GCM streamed
// in chunks. On-disk format:
//
//	[magic 4 = "MB\x02\x01"] [file nonce 12] [chunk size 4 BE]
//	{ chunk1 } { chunk2 } ... { final chunk }
//
// Each encrypted chunk is plaintext + 16-byte GCM tag. Chunk nonce is
// derived fileNonce XOR chunkIndex. AAD:
//
//	chunk 0 (not final): header                     (20 bytes)
//	chunk 0 (final):     header || 0x01             (21 bytes)
//	chunk i (not final): 0x00                       (1 byte)
//	chunk i (final):     0x01                       (1 byte)
//
// The final-flag byte binds the "this is the last chunk" claim into
// the GCM tag: an attacker who drops the real final chunk(s) would
// have to recompute the tag of the new last chunk with flag=0x01,
// which they cannot without the key.
//
// An empty plaintext file still emits one zero-length chunk carrying
// the final flag, so truncation-to-header is detected on decrypt.
func EncryptFile(key []byte, srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating destination: %w", err)
	}
	defer func() { _ = dst.Close() }()

	bufSrc := bufio.NewReaderSize(src, ioBufferSize)
	bufDst := bufio.NewWriterSize(dst, ioBufferSize)

	gcm, err := newGCM(key)
	if err != nil {
		return err
	}

	fileNonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(fileNonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	header := make([]byte, FileHeaderSize)
	copy(header[0:4], fileMagic[:])
	copy(header[4:16], fileNonce)
	binary.BigEndian.PutUint32(header[16:20], ChunkSize)
	if _, err := bufDst.Write(header); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	// We need to know whether a chunk is the last one at encrypt time.
	// Read one chunk ahead: hold the current chunk in memory; once we
	// know a further chunk exists, emit the held chunk as non-final.
	// When the read loop ends, emit the held chunk (or an empty final
	// chunk for empty files) with the final flag.
	var (
		held    []byte
		heldIdx uint64
		nextIdx uint64
		inbuf   = make([]byte, ChunkSize)
	)

	emit := func(payload []byte, idx uint64, isFinal bool) error {
		aad := buildAAD(header, idx, isFinal)
		chunkNonce := deriveChunkNonce(fileNonce, idx)
		enc := gcm.Seal(nil, chunkNonce, payload, aad)
		if _, err := bufDst.Write(enc); err != nil {
			return fmt.Errorf("writing chunk %d: %w", idx, err)
		}
		return nil
	}

	for {
		n, readErr := io.ReadFull(bufSrc, inbuf)
		if n > 0 {
			if held != nil {
				if err := emit(held, heldIdx, false); err != nil {
					return err
				}
			}
			held = append(held[:0], inbuf[:n]...)
			heldIdx = nextIdx
			nextIdx++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("reading chunk %d: %w", nextIdx, readErr)
		}
	}

	// Emit final chunk. Empty-file case: held is nil, emit empty final
	// at index 0 so decrypt still sees a final-flagged chunk.
	if held == nil {
		if err := emit(nil, 0, true); err != nil {
			return err
		}
	} else {
		if err := emit(held, heldIdx, true); err != nil {
			return err
		}
	}

	if err := bufDst.Flush(); err != nil {
		return fmt.Errorf("flushing buffer: %w", err)
	}
	// Per-file fsync removed: callers (LockFolder/LockFile) now batch
	// fsync in chunks, then issue a final sync before deleting the
	// originals. Per-file fsync was the dominant cost on vaults with
	// many small files.
	return nil
}

// DecryptFile decrypts srcPath to dstPath. Rejects any ciphertext
// whose first 4 bytes don't match fileMagic, and any well-formed
// ciphertext whose stream ends without a final-flagged chunk.
func DecryptFile(key []byte, srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating destination: %w", err)
	}
	defer func() { _ = dst.Close() }()

	bufSrc := bufio.NewReaderSize(src, ioBufferSize)
	bufDst := bufio.NewWriterSize(dst, ioBufferSize)

	gcm, err := newGCM(key)
	if err != nil {
		return err
	}

	header := make([]byte, FileHeaderSize)
	if _, err := io.ReadFull(bufSrc, header); err != nil {
		return fmt.Errorf("reading header: %w", err)
	}
	var magic [4]byte
	copy(magic[:], header[0:4])
	if magic != fileMagic {
		return fmt.Errorf("bad magic %x, expected %x", magic, fileMagic)
	}

	fileNonce := header[4:16]
	chunkSize := binary.BigEndian.Uint32(header[16:20])
	if chunkSize == 0 || chunkSize > 16*1024*1024 {
		return fmt.Errorf("implausible chunk size %d", chunkSize)
	}
	encChunkSize := int(chunkSize) + gcm.Overhead()
	buf := make([]byte, encChunkSize)

	open := func(payload []byte, idx uint64, isFinal bool) ([]byte, error) {
		aad := buildAAD(header, idx, isFinal)
		return gcm.Open(nil, deriveChunkNonce(fileNonce, idx), payload, aad)
	}

	var (
		held    []byte
		heldIdx uint64
		nextIdx uint64
		sawAny  bool
	)

	for {
		n, readErr := io.ReadFull(bufSrc, buf)
		if n > 0 {
			sawAny = true
			if held != nil {
				pt, err := open(held, heldIdx, false)
				if err != nil {
					return fmt.Errorf("decrypting chunk %d: %w", heldIdx, err)
				}
				if _, err := bufDst.Write(pt); err != nil {
					return fmt.Errorf("writing chunk %d: %w", heldIdx, err)
				}
			}
			held = append(held[:0], buf[:n]...)
			heldIdx = nextIdx
			nextIdx++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("reading chunk %d: %w", nextIdx, readErr)
		}
	}
	if !sawAny {
		return ErrTruncatedCiphertext
	}
	pt, err := open(held, heldIdx, true)
	if err != nil {
		return ErrTruncatedCiphertext
	}
	if _, err := bufDst.Write(pt); err != nil {
		return fmt.Errorf("writing final chunk: %w", err)
	}
	return bufDst.Flush()
}

// buildAAD constructs the additional-authenticated-data for a chunk.
// First chunk binds the header; every chunk binds the final-flag. The
// AAD must match on encrypt + decrypt or the GCM tag fails.
func buildAAD(header []byte, chunkIdx uint64, isFinal bool) []byte {
	flag := chunkFlagNonFinal
	if isFinal {
		flag = chunkFlagFinal
	}
	if chunkIdx == 0 {
		out := make([]byte, 0, len(header)+1)
		out = append(out, header...)
		out = append(out, flag)
		return out
	}
	return []byte{flag}
}

// deriveChunkNonce XORs the file nonce with the chunk index to produce a unique
// nonce per chunk without requiring additional random bytes.
func deriveChunkNonce(fileNonce []byte, chunkIdx uint64) []byte {
	nonce := make([]byte, len(fileNonce))
	copy(nonce, fileNonce)
	idxBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(idxBytes, chunkIdx)
	for i := range 8 {
		nonce[len(nonce)-8+i] ^= idxBytes[i]
	}
	return nonce
}
