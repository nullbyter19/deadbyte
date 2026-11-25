package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// NewKeypair generates a fresh X25519 keypair (Curve25519 ECDH).
func NewKeypair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey(), nil
}

// PublicKeyFromBytes parses a raw 32-byte X25519 public key.
func PublicKeyFromBytes(b []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(b)
}

func PubToB64(pub *ecdh.PublicKey) string { return base64.StdEncoding.EncodeToString(pub.Bytes()) }

// ParsePubB64 parses a base64-encoded X25519 public key.
func ParsePubB64(s string) (*ecdh.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return PublicKeyFromBytes(b)
}
func PrivToB64(priv *ecdh.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.Bytes())
}

// PrivFromBytes parses a raw 32-byte X25519 private key.
func PrivFromBytes(b []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(b)
}

func ParsePrivB64(s string) (*ecdh.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(b)
}

// masterKeyBlobPrefix identifies an Argon2id+AES-GCM sealed master key.
const masterKeyBlobPrefix = "DBKY1"

// SealMasterKey encrypts a raw 32-byte private key under a passphrase using
// Argon2id (key derivation) and AES-256-GCM (sealing).
func SealMasterKey(priv []byte, pass string) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("crypto: private key must be 32 bytes")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(pass), salt, 3, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, priv, nil)
	blob := make([]byte, 0, len(masterKeyBlobPrefix)+16+len(nonce)+len(ct))
	blob = append(blob, masterKeyBlobPrefix...)
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return blob, nil
}

// OpenMasterKey reverses SealMasterKey.
func OpenMasterKey(blob []byte, pass string) ([]byte, error) {
	if len(blob) < len(masterKeyBlobPrefix)+16+12+16 {
		return nil, errors.New("crypto: malformed master key blob")
	}
	if string(blob[:len(masterKeyBlobPrefix)]) != masterKeyBlobPrefix {
		return nil, errors.New("crypto: unknown master key blob format")
	}
	p := len(masterKeyBlobPrefix)
	salt := blob[p : p+16]
	p += 16
	nonce := blob[p : p+12]
	p += 12
	ct := blob[p:]
	key := argon2.IDKey([]byte(pass), salt, 3, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: wrong master secret: %w", err)
	}
	return pt, nil
}
