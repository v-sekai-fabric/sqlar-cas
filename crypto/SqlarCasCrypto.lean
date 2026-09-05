namespace SqlarCasCrypto

abbrev FileKey   := ByteArray
abbrev DekId     := ByteArray
abbrev X25519Pub := ByteArray
abbrev X25519Priv := ByteArray

opaque hkdfSha256 (ikm salt : ByteArray) (info : String) (outLen : Nat) : ByteArray
opaque hmacSha256 (key msg : ByteArray) : ByteArray
opaque chacha20Poly1305Encrypt (key nonce plaintext aad : ByteArray) : ByteArray
opaque chacha20Poly1305Decrypt (key nonce ciphertextAndTag aad : ByteArray) : Option ByteArray
opaque x25519 (priv : X25519Priv) (pub : X25519Pub) : ByteArray

def wrapNonce : ByteArray :=
  ByteArray.mk #[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

def x25519WrapKey (ephPriv : X25519Priv) (recipPub ephPub : X25519Pub) : ByteArray :=
  hkdfSha256 (x25519 ephPriv recipPub) (ephPub ++ recipPub)
             "age-encryption.org/v1/X25519" 32

def payloadKey (fk : FileKey) (payloadNonce : ByteArray) : ByteArray :=
  hkdfSha256 fk payloadNonce "payload" 32

def macKey (fk : FileKey) : ByteArray :=
  hkdfSha256 fk ByteArray.empty "header" 32

opaque wrapX25519 (recipientPub : X25519Pub) (fk : FileKey) : ByteArray
opaque unwrapX25519 (recipientPriv : X25519Priv) (wrapped : ByteArray) : Option FileKey

end SqlarCasCrypto
