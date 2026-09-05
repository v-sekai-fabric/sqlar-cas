import SqlarCasCrypto

/-!
`sqlar.data` envelope in the age v1.1.0 construction (c2sp.org/age@v1.1.0).

Header carries {version, dek_id, payload_nonce}. No `alg` byte:
a different AEAD / KDF / MAC / wrap is a `version` bump on the whole
envelope, not a per-field vocabulary.

Header MAC is age's HMAC-SHA-256 over headerBytes with mac_key =
HKDF-SHA-256(file_key, salt=empty, info="header"). Row identity —
`sqlar.name` — is bound into headerBytes so ciphertext-move across
rows fails MAC verify without recomputation.
-/
namespace SqlarCasEnvelope

open SqlarCasCrypto

/-- The `sqlar.data` header for an encrypted caibx. -/
structure Header where
  version      : UInt8        -- format version (currently 1)
  dekId        : DekId        -- 16B opaque, matches sqlar_dek_wraps.dek_id
  payloadNonce : ByteArray    -- 16B age STREAM per-file nonce
  deriving Inhabited

/-- Encode the header into its 33-byte on-disk form:
    `[version:1][dek_id:16][payload_nonce:16]`. -/
opaque encodeHeader : Header → ByteArray

/-- Parse the header off the front of `sqlar.data`. Returns
    `(header, remaining bytes)`. -/
opaque parseHeader : ByteArray → Option (Header × ByteArray)

/-- Header bytes covered by HMAC-SHA-256, including the row's name so
    row identity is bound the way age binds a file's stanzas.
      headerBytes = encodeHeader h ‖ name.toUTF8 -/
def headerBytes (h : Header) (name : String) : ByteArray :=
  encodeHeader h ++ name.toUTF8

/-- Allocate a fresh file_key, encrypt the caibx via ChaCha20-Poly1305
    STREAM under payload_key = HKDF(file_key, payload_nonce, "payload"),
    compute the header MAC under mac_key = HKDF(file_key, ∅, "header"),
    return `(file_key, dek_id, sqlar_data_blob)`. The caller wraps
    `file_key` for each authorized recipient via
    `SqlarCasCrypto.wrapX25519`. -/
opaque wrapCaibx (caibx : ByteArray) (name : String)
    : FileKey × DekId × ByteArray

/-- Given a file_key (obtained via `SqlarCasCrypto.unwrapX25519`), the
    on-disk `sqlar.data`, and the row's `name`, verify the header MAC
    and STREAM-decrypt the caibx. `none` on MAC mismatch, tag mismatch,
    or malformed input. -/
opaque unwrapCaibx (fk : FileKey) (sqlarData : ByteArray) (name : String)
    : Option ByteArray

end SqlarCasEnvelope
