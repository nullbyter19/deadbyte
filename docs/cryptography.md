# DeadByte — Cryptographic scheme

## Overview

```
Operator                                Payload (target)
--------                                ----------------
(X25519 master keypair)                 embeds only the PUBLIC KEY
private key sealed on the C2            (Argon2id+AES-GCM, "DBKY1")
```

Per file, the payload generates:

```
fileKey   = 32 random bytes (the file key)
ephemeral = X25519 ephemeral key (new per file)

shared    = ECDH(ephemeral_priv, master_pub)
KEK       = HKDF-SHA256(shared, salt="DeadByte-v1", info="filekey-v1", 32B)
wrapped   = AES-256-GCM(KEK, nonce=wrapNonce[12B]).Seal(fileKey)

fnKey     = HKDF-SHA256(fileKey, wrapNonce, info="fname-key-v1", 32B)
fnNonce   = HKDF-SHA256(fileKey, wrapNonce, info="fname-nonce-v1", 12B)
nameEnc   = AES-256-GCM(fnKey, fnNonce).Seal(original_filename)
```

File data: `AES-256-GCM(fileKey)` in `ChunkSize = 1 MiB` blocks.

## Per-block nonce (age STREAM style)

Each block uses a 12-byte nonce: `[4 bytes: big-endian counter][8 bytes: zero]`.
The counter starts at 0 and increments for every block. This eliminates nonce reuse and
allows on-demand decryption (block N depends only on counter N).

## Encrypted file format

```
[8]  magic    "DBYTE001"
[1]  version  (1)
[32] ephemeral public key (X25519)
[12] wrapNonce
[48] wrapped file key (32B ciphertext + 16B GCM tag)
[4]  encrypted original name length (big endian)
[N]  encrypted original name (AES-256-GCM, authenticated)
...  1 MiB ciphertext blocks (each +16B tag)
```

The header is self-contained: recovering a file only requires the **master private key**
(ECDH with the header's ephemeral key). There is no cleartext metadata beyond the
magic/version — names and contents stay confidential until decryption.

## Master key at rest (C2)

```
sealed = "DBKY1" || salt[16] || nonce[12] || AES-256-GCM(Argon2id(pass, salt)).Seal(priv32)
Argon2id: time=3, mem=64 MiB, threads=4 (OWASP defaults)
```

Exporting the private key through the API requires the admin token **and** the master
secret (or the secret configured on the server). The cleartext private key is never
persisted.

## Properties

- **Confidentiality**: AES-256-GCM with unique per-file keys; leaking one `fileKey` does
  not compromise the other files.
- **Integrity/authentication**: GCM authenticates every block; any change to the ciphertext
  makes decryption of that block fail.
- **Forward secrecy**: the per-file ephemeral key prevents capturing a session key (KEK)
  from compromising earlier files.
- **No cleartext metadata**: file names are encrypted; only the `.deadbyte` suffix and the
  magic identify affected files.

## Implementation references

- `internal/crypto/keys.go` — keypair, serialization, master key sealing
- `internal/crypto/header.go` — `DBYTE001` header
- `internal/crypto/seal.go` — HKDF, KEK, EncryptFile/DecryptFile/OpenFileHeader
