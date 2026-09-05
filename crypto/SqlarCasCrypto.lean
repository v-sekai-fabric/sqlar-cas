/-!
Age v1.1.0 primitives (c2sp.org/age@v1.1.0).

* HKDF-SHA-256, HMAC-SHA-256, ChaCha20-Poly1305, X25519.
* File key is 16 bytes (age §"File Key"), not 32.
* Wrap AEAD nonce is 12 zero bytes; STREAM per-chunk nonce is
  11-byte BE counter ‖ (0x01 last, else 0x00).
* Wrap key derivation follows age's X25519 recipient stanza verbatim.
-/
namespace SqlarCasCrypto

/-- Age's 16-byte file key. -/
abbrev FileKey := ByteArray

/-- 16-byte opaque file-key identifier (random at file creation). -/
abbrev DekId := ByteArray

/-- 32-byte X25519 public key. -/
abbrev X25519Pub := ByteArray

/-- 32-byte X25519 private key. -/
abbrev X25519Priv := ByteArray

/-- HKDF-SHA-256(ikm, salt, info, outLen). -/
opaque hkdfSha256 (ikm salt : ByteArray) (info : String) (outLen : Nat) : ByteArray

/-- HMAC-SHA-256(key, msg). -/
opaque hmacSha256 (key msg : ByteArray) : ByteArray

/-- ChaCha20-Poly1305 encrypt: returns `[ciphertext ‖ 16B tag]`.
    `aad` is the additional authenticated data (bytes over which the
    tag is computed but which are not part of the ciphertext output). -/
opaque chacha20Poly1305Encrypt
  (key nonce plaintext aad : ByteArray) : ByteArray

/-- ChaCha20-Poly1305 decrypt. `none` on tag mismatch. -/
opaque chacha20Poly1305Decrypt
  (key nonce ciphertextAndTag aad : ByteArray) : Option ByteArray

/-- X25519(privateKey, peerPublicKey) → 32-byte shared secret. -/
opaque x25519 (priv : X25519Priv) (pub : X25519Pub) : ByteArray

/-- 12 zero bytes — age uses this as the wrap AEAD nonce. -/
def wrapNonce : ByteArray :=
  ByteArray.mk #[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

/-- Age's X25519 recipient wrap-key derivation:
    HKDF-SHA-256(
      ikm  = X25519(ephPriv, recipPub),
      salt = ephPub ‖ recipPub,
      info = "age-encryption.org/v1/X25519",
      out  = 32). -/
def x25519WrapKey
    (ephPriv : X25519Priv) (recipPub ephPub : X25519Pub) : ByteArray :=
  hkdfSha256 (x25519 ephPriv recipPub) (ephPub ++ recipPub)
             "age-encryption.org/v1/X25519" 32

/-- Age's payload-key derivation:
    HKDF-SHA-256(file_key, salt=payload_nonce, info="payload"). -/
def payloadKey (fk : FileKey) (payloadNonce : ByteArray) : ByteArray :=
  hkdfSha256 fk payloadNonce "payload" 32

/-- Age's header-MAC-key derivation:
    HKDF-SHA-256(file_key, salt=empty, info="header"). -/
def macKey (fk : FileKey) : ByteArray :=
  hkdfSha256 fk ByteArray.empty "header" 32

/-- Age-style X25519 wrap: fresh ephemeral pair + ChaCha20-Poly1305 over
    the 16-byte file key. Output layout: `[ephPub:32 ‖ ct:16 ‖ tag:16]`.
    Self-contained; the recipient's private key alone unwraps. -/
opaque wrapX25519 (recipientPub : X25519Pub) (fk : FileKey) : ByteArray

/-- Unwrap using the recipient's private key. `none` on tag mismatch. -/
opaque unwrapX25519 (recipientPriv : X25519Priv) (wrapped : ByteArray)
    : Option FileKey

end SqlarCasCrypto
