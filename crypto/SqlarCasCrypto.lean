namespace SqlarCasCrypto

/-- 32-byte data encryption key. -/
abbrev DEK := ByteArray

/-- 12-byte AES-256-GCM nonce. -/
abbrev Nonce12 := ByteArray

/-- 32-byte X25519 public key. -/
abbrev X25519Pub := ByteArray

/-- 32-byte X25519 private key. -/
abbrev X25519Priv := ByteArray

/-- 16-byte opaque DEK identifier (random at file creation). -/
abbrev DekId := ByteArray

/-- AES-256-GCM encrypt: returns `[ciphertext || 16B tag]`. -/
opaque aeadEncrypt (key : DEK) (nonce : Nonce12) (plaintext : ByteArray) : ByteArray

/-- AES-256-GCM decrypt. `none` on tag mismatch. -/
opaque aeadDecrypt (key : DEK) (nonce : Nonce12) (ciphertextAndTag : ByteArray)
    : Option ByteArray

/-- age-style X25519 wrap: fresh ephemeral X25519 pair + ChaCha20-Poly1305 over
    the DEK. Output layout: `[ephemeral_pub:32 || nonce:12 || ct:32 || tag:16]`.
    Zero external state — self-contained wrap; static-Pages friendly. -/
opaque wrapAge (recipientPub : X25519Pub) (dek : DEK) : ByteArray

/-- Unwrap using the recipient's private key. `none` on tag mismatch. -/
opaque unwrapAge (recipientPriv : X25519Priv) (wrapped : ByteArray) : Option DEK

end SqlarCasCrypto
