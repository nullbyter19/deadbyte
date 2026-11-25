package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ChunkSize is the authenticated-encryption chunk size (1 MiB). Each chunk is
// encrypted with AES-256-GCM using a 32-bit big-endian counter in the first
// four bytes of the nonce (the same construction used by age's STREAM mode).
const ChunkSize = 1 << 20

// FileInfo describes a successfully sealed/opened file.
type FileInfo struct {
	OrigName string
	Size     int64
	ModTime  time.Time
}

func hkdfBytes(secret, salt, info []byte, n int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// kekFromShared derives the key-encryption key from an X25519 shared secret.
func kekFromShared(shared []byte) ([]byte, error) {
	return hkdfBytes(shared, []byte("DeadByte-v1"), []byte("filekey-v1"), 32)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncryptFile seals a file using the recipient's master public key.
// The file key is random per file; the header carries an ephemeral X25519
// public key so the holder of the master private key can recover it.
func EncryptFile(recipient *ecdh.PublicKey, inPath, outPath string) (*FileInfo, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return nil, err
	}

	fileKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, fileKey); err != nil {
		return nil, err
	}
	wrapNonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, wrapNonce); err != nil {
		return nil, err
	}
	ephPriv, ephPub, err := NewKeypair()
	if err != nil {
		return nil, err
	}
	shared, err := ephPriv.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	kek, err := kekFromShared(shared)
	if err != nil {
		return nil, err
	}

	kgcm, err := gcm(kek)
	if err != nil {
		return nil, err
	}
	wrapped := kgcm.Seal(nil, wrapNonce, fileKey, nil)

	fnKey, err := hkdfBytes(fileKey, wrapNonce, []byte("fname-key-v1"), 32)
	if err != nil {
		return nil, err
	}
	fnNonce, err := hkdfBytes(fileKey, wrapNonce, []byte("fname-nonce-v1"), 12)
	if err != nil {
		return nil, err
	}
	fngcm, err := gcm(fnKey)
	if err != nil {
		return nil, err
	}
	nameEnc := fngcm.Seal(nil, fnNonce, []byte(st.Name()), nil)

	hdr := &Header{
		EphemeralPub: ephPub.Bytes(),
		WrapNonce:    wrapNonce,
		WrappedKey:   wrapped,
		OrigNameEnc:  nameEnc,
	}

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	cleanup := func() { out.Close(); os.Remove(outPath) }

	if _, err := out.Write(hdr.Encode()); err != nil {
		cleanup()
		return nil, err
	}

	fgcm, err := gcm(fileKey)
	if err != nil {
		cleanup()
		return nil, err
	}

	var counter uint32
	buf := make([]byte, ChunkSize)
	for {
		n, rerr := io.ReadFull(in, buf)
		if n > 0 {
			nonce := make([]byte, 12)
			binary.BigEndian.PutUint32(nonce[:4], counter)
			counter++
			ct := fgcm.Seal(nil, nonce, buf[:n], nil)
			if _, werr := out.Write(ct); werr != nil {
				cleanup()
				return nil, werr
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			cleanup()
			return nil, rerr
		}
		if n == 0 {
			break
		}
	}
	if err := out.Sync(); err != nil {
		cleanup()
		return nil, err
	}
	if err := out.Close(); err != nil {
		os.Remove(outPath)
		return nil, err
	}
	if err := os.Chtimes(outPath, st.ModTime(), st.ModTime()); err != nil {
		os.Remove(outPath)
		return nil, err
	}
	return &FileInfo{OrigName: st.Name(), Size: st.Size(), ModTime: st.ModTime()}, nil
}

// DecryptFile restores a sealed file using the master private key.
func DecryptFile(master *ecdh.PrivateKey, inPath, outPath string) (*FileInfo, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	head := make([]byte, HeaderOverhead+4096)
	n, err := io.ReadAtLeast(in, head, HeaderOverhead)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	head = head[:n]
	hdr, hdrLen, err := ParseHeader(head)
	if err != nil {
		return nil, err
	}

	ephPub, err := PublicKeyFromBytes(hdr.EphemeralPub)
	if err != nil {
		return nil, err
	}
	shared, err := master.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	kek, err := kekFromShared(shared)
	if err != nil {
		return nil, err
	}
	kgcm, err := gcm(kek)
	if err != nil {
		return nil, err
	}
	fileKey, err := kgcm.Open(nil, hdr.WrapNonce, hdr.WrappedKey, nil)
	if err != nil {
		return nil, errors.New("crypto: cannot unwrap file key (wrong master key?)")
	}

	fnKey, err := hkdfBytes(fileKey, hdr.WrapNonce, []byte("fname-key-v1"), 32)
	if err != nil {
		return nil, err
	}
	fnNonce, err := hkdfBytes(fileKey, hdr.WrapNonce, []byte("fname-nonce-v1"), 12)
	if err != nil {
		return nil, err
	}
	fngcm, err := gcm(fnKey)
	if err != nil {
		return nil, err
	}
	origName, err := fngcm.Open(nil, fnNonce, hdr.OrigNameEnc, nil)
	if err != nil {
		return nil, errors.New("crypto: filename authentication failed")
	}

	fgcm, err := gcm(fileKey)
	if err != nil {
		return nil, err
	}

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	cleanup := func() { out.Close(); os.Remove(outPath) }

	var counter uint32
	// Skip the header already consumed; if the header didn't fill the buffer,
	// position the reader correctly.
	if int64(hdrLen) != int64(n) {
		if _, err := in.Seek(int64(hdrLen), io.SeekStart); err != nil {
			cleanup()
			return nil, err
		}
	} else {
		// Header exactly filled the read: remaining ciphertext starts at hdrLen.
		if _, err := in.Seek(int64(hdrLen), io.SeekStart); err != nil {
			cleanup()
			return nil, err
		}
	}

	buf := make([]byte, ChunkSize+16)
	var total int64
	for {
		m, rerr := io.ReadFull(in, buf)
		if m > 0 {
			nonce := make([]byte, 12)
			binary.BigEndian.PutUint32(nonce[:4], counter)
			counter++
			pt, oerr := fgcm.Open(nil, nonce, buf[:m], nil)
			if oerr != nil {
				cleanup()
				return nil, errors.New("crypto: chunk authentication failed (corrupt or tampered)")
			}
			if _, werr := out.Write(pt); werr != nil {
				cleanup()
				return nil, werr
			}
			total += int64(len(pt))
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			cleanup()
			return nil, rerr
		}
		if m == 0 {
			break
		}
	}
	if err := out.Sync(); err != nil {
		cleanup()
		return nil, err
	}
	if err := out.Close(); err != nil {
		os.Remove(outPath)
		return nil, err
	}
	if err := os.Chtimes(outPath, time.Now(), time.Now()); err != nil {
		os.Remove(outPath)
		return nil, err
	}
	return &FileInfo{OrigName: string(origName), Size: total}, nil
}

// OpenFileHeader unwraps a sealed file's metadata (original filename) without
// writing any data. It is used for dry-run verification and recovery planning.
func OpenFileHeader(master *ecdh.PrivateKey, inPath string) (string, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return "", err
	}
	defer in.Close()
	head := make([]byte, HeaderOverhead+4096)
	n, err := io.ReadAtLeast(in, head, HeaderOverhead)
	if err != nil && err != io.ErrUnexpectedEOF {
		return "", err
	}
	head = head[:n]
	hdr, _, err := ParseHeader(head)
	if err != nil {
		return "", err
	}
	ephPub, err := PublicKeyFromBytes(hdr.EphemeralPub)
	if err != nil {
		return "", err
	}
	shared, err := master.ECDH(ephPub)
	if err != nil {
		return "", err
	}
	kek, err := kekFromShared(shared)
	if err != nil {
		return "", err
	}
	kgcm, err := gcm(kek)
	if err != nil {
		return "", err
	}
	fileKey, err := kgcm.Open(nil, hdr.WrapNonce, hdr.WrappedKey, nil)
	if err != nil {
		return "", errors.New("crypto: cannot unwrap file key (wrong master key?)")
	}
	fnKey, err := hkdfBytes(fileKey, hdr.WrapNonce, []byte("fname-key-v1"), 32)
	if err != nil {
		return "", err
	}
	fnNonce, err := hkdfBytes(fileKey, hdr.WrapNonce, []byte("fname-nonce-v1"), 12)
	if err != nil {
		return "", err
	}
	fngcm, err := gcm(fnKey)
	if err != nil {
		return "", err
	}
	orig, err := fngcm.Open(nil, fnNonce, hdr.OrigNameEnc, nil)
	if err != nil {
		return "", errors.New("crypto: filename authentication failed")
	}
	return string(orig), nil
}

// LooksLikeDeadByte checks the magic bytes of a file.
func LooksLikeDeadByte(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 8)
	if _, err := io.ReadFull(f, b); err != nil {
		return false
	}
	return string(b) == headerMagic
}
