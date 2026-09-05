import SqlarCasCrypto
import SqlarCasEnvelope
import SqlarCasZstd
import SqlarCasHash
import SqlarCasIndex

/-!
`sqlar` + `sqlar_chunks` table shapes and the reassembler.

Chunks are ChaCha20-Poly1305 STREAM ciphertext under a per-file payload
key derived via HKDF from the row's file_key. Chunk id is
SHA-512/256(ct) — casync convention on the ciphertext.

`sqlar.data` is the envelope blob; `sqlar.sz` is the reassembled
plaintext size, strictly greater than `data.size` (a `sqlar.sz > sqlar.data.size`
invariant that rules out sqlar-native zlib).
-/
namespace SqlarCasSqlar

open SqlarCasCrypto SqlarCasHash SqlarCasIndex

/-- One row of the `sqlar` table. `data` is the envelope blob. -/
structure Row where
  name  : String
  mode  : UInt32
  mtime : Int64
  sz    : UInt64
  data  : ByteArray
  dekId : DekId
  deriving Inhabited

/-- One row of `sqlar_chunks`. Ciphertext, content-addressed by
    SHA-512/256 of the ciphertext bytes. -/
structure ChunkRow where
  hash : SqlarCasIndex.ChunkId      -- SHA-512/256(ct)
  ct   : ByteArray    -- ChaCha20-Poly1305-STREAM(payload_key, stream_nonce, zstd(raw))
  deriving Inhabited

/-- Reassemble a file from a caibx + a chunk fetcher + the file_key
    (needed to derive payload_key for STREAM decrypt). The fetcher
    returns raw `ct` bytes; the reassembler decrypts under payload_key,
    zstd-decodes, verifies plaintext SHA-512/256 against the caibx,
    and concatenates. `none` if any step fails. -/
opaque reassemble
    (caibx : Caibx)
    (fk    : FileKey)
    (payloadNonce : ByteArray)
    (fetch : SqlarCasIndex.ChunkId → Option ByteArray)
    : Option ByteArray

end SqlarCasSqlar
