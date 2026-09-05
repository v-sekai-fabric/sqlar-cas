import SqlarCasCrypto

/-!
`sqlar_dek_wraps` — one wrap per authorized principal per file_key.

One wrap construction (age's X25519 recipient stanza) — no `wrap_alg`
column. A different wrap construction is a version bump on the
envelope, not a new column value.

The wrapped-key body is fixed-shape:
  [ ephemeralPub : 32 ] [ ciphertext : 16 ] [ tag : 16 ]
with wrapping key derived per age:
  wrap_key = HKDF-SHA-256(
    ikm  = X25519(ephPriv, recipient_pub),
    salt = ephPub ‖ recipient_pub,
    info = "age-encryption.org/v1/X25519",
    out  = 32)
  ciphertext ‖ tag = ChaCha20-Poly1305(wrap_key, 12×0x00, file_key)
-/
namespace SqlarCasWraps

open SqlarCasCrypto

/-- One row of `sqlar_dek_wraps`. -/
structure Row where
  dekId        : DekId
  principalId  : String
  ephemeralPub : X25519Pub    -- 32 B, the wrap's ephemeral half
  wrappedKey   : ByteArray    -- 32 B: 16 B ct ‖ 16 B tag
  grantedAt    : Int64
  grantedBy    : String
  deriving Inhabited

/-- One row of `sqlar_principal_keys` — recipients' X25519 public halves.
    Private halves stay in each recipient's keystore. -/
structure PrincipalKey where
  principalId : String
  publicKey   : X25519Pub
  deriving Inhabited

end SqlarCasWraps
