// Package obfs provides trivial XOR+base64 string obfuscation so that
// sensitive constants (C2 URLs, filenames, branding) do not appear in
// plaintext inside the binary. Generate literals with cmd/xorgen.
package obfs

import "encoding/base64"

// S decodes a base64 payload and XORs it with key.
func S(payload string, key byte) string {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	out := make([]byte, len(raw))
	for i := range raw {
		out[i] = raw[i] ^ key
	}
	return string(out)
}
