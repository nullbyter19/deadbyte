package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// File header layout (self-contained per encrypted file):
//
//	[8]  magic  "DBYTE001"
//	[1]  version (1)
//	[32] ephemeral X25519 public key (recipient wrapping)
//	[12] wrap nonce
//	[48] wrapped file key (AES-256-GCM: 32B key + 16B tag)
//	[4]  encrypted original filename length (big endian)
//	[N]  encrypted original filename (AES-256-GCM)
//	...  chunked AES-256-GCM ciphertext
const (
	headerMagic    = "DBYTE001"
	HeaderVersion  = 1
	HeaderOverhead = 8 + 1 + 32 + 12 + 48 + 4 // bytes before filename ciphertext
)

// Header is the parsed metadata of an encrypted file.
type Header struct {
	EphemeralPub []byte // 32
	WrapNonce    []byte // 12
	WrappedKey   []byte // 48
	OrigNameEnc  []byte // ciphertext of the original filename
}

func (h *Header) Encode() []byte {
	buf := make([]byte, 0, HeaderOverhead+len(h.OrigNameEnc))
	buf = append(buf, headerMagic...)
	buf = append(buf, HeaderVersion)
	buf = append(buf, h.EphemeralPub...)
	buf = append(buf, h.WrapNonce...)
	buf = append(buf, h.WrappedKey...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(h.OrigNameEnc)))
	buf = append(buf, l[:]...)
	buf = append(buf, h.OrigNameEnc...)
	return buf
}

// ParseHeader decodes an encrypted file header.
func ParseHeader(b []byte) (*Header, int, error) {
	if len(b) < HeaderOverhead {
		return nil, 0, errors.New("crypto: header too short")
	}
	if string(b[:8]) != headerMagic {
		return nil, 0, errors.New("crypto: not a DeadByte file (bad magic)")
	}
	if b[8] != HeaderVersion {
		return nil, 0, fmt.Errorf("crypto: unsupported header version %d", b[8])
	}
	fnLen := int(binary.BigEndian.Uint32(b[HeaderOverhead-4 : HeaderOverhead]))
	if fnLen < 0 || fnLen > 4096 {
		return nil, 0, errors.New("crypto: invalid filename length")
	}
	total := HeaderOverhead + fnLen
	if len(b) < total {
		return nil, 0, errors.New("crypto: truncated header")
	}
	return &Header{
		EphemeralPub: append([]byte(nil), b[9:41]...),
		WrapNonce:    append([]byte(nil), b[41:53]...),
		WrappedKey:   append([]byte(nil), b[53:101]...),
		OrigNameEnc:  append([]byte(nil), b[HeaderOverhead:total]...),
	}, total, nil
}
