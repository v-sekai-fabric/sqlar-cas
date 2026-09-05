import SqlarCasCrypto

namespace SqlarCasEnvelope

open SqlarCasCrypto

/-- The `sqlar.data` header for an encrypted caibx. -/
structure Header where
  version : UInt8        -- format version (currently 1)
  alg     : UInt8        -- cipher id: 0x01 = AES-256-GCM
  dekId   : DekId        -- 16B opaque DEK id, matches `sqlar_dek_wraps.dek_id`
  nonce   : Nonce12      -- 12B AES-GCM nonce
  deriving Repr, Inhabited

/-- Encode the header into its 30-byte on-disk form:
    `[version:1][alg:1][dek_id:16][nonce:12]`. -/
opaque encodeHeader : Header → ByteArray

/-- Parse the header off the front of `sqlar.data`. Returns `(header, remaining bytes)`. -/
opaque parseHeader : ByteArray → Option (Header × ByteArray)

/-- Allocate a fresh DEK, encrypt the caibx, return `(dek, dek_id, sqlar_data_blob)`.
    The caller wraps `dek` for each authorized recipient via `SqlarCasCrypto.wrapAge`. -/
opaque wrapCaibx (caibx : ByteArray) : DEK × DekId × ByteArray

/-- Given a DEK (obtained via `SqlarCasCrypto.unwrapAge`) and the on-disk `sqlar.data`,
    decrypt and return the caibx bytes. `none` on tag mismatch or malformed input. -/
opaque unwrapCaibx (dek : DEK) (sqlarData : ByteArray) : Option ByteArray

end SqlarCasEnvelope
