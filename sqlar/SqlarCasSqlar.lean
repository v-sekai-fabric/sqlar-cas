import SqlarCasCrypto
import SqlarCasEnvelope
import SqlarCasZstd
import SqlarCasHash
import SqlarCasIndex

namespace SqlarCasSqlar

open SqlarCasCrypto SqlarCasHash SqlarCasIndex

/-- One row of the `sqlar` table. `data` = `SqlarCasEnvelope`-shaped blob;
    `sz` = the reassembled file size, strictly greater than `data.size`. -/
structure Row where
  name  : String
  mode  : UInt32
  mtime : Int64
  sz    : UInt64
  data  : ByteArray
  dekId : DekId
  deriving Repr, Inhabited

/-- One row of the `sqlar_chunks` table. Plaintext (zstd-compressed), content-addressed.
    `hash = SqlarCasHash.sha512_256(SqlarCasZstd.decode data)`. -/
structure ChunkRow where
  hash : ChunkId
  data : ByteArray
  deriving Repr, Inhabited

/-- Reassemble a file from a caibx + a chunk fetcher (which does the zstd decode
    and hash-verify per fetch). `none` if any chunk is missing or verify fails. -/
opaque reassemble
    (caibx : Caibx)
    (fetch : ChunkId → Option ByteArray)
    : Option ByteArray

end SqlarCasSqlar
