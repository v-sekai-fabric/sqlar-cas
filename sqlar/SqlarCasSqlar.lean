import SqlarCasCrypto
import SqlarCasEnvelope
import SqlarCasZstd
import SqlarCasHash
import SqlarCasIndex

namespace SqlarCasSqlar

open SqlarCasCrypto SqlarCasHash SqlarCasIndex

structure Row where
  name  : String
  mode  : UInt32
  mtime : Int64
  sz    : UInt64
  data  : ByteArray
  dekId : DekId
  deriving Inhabited

structure ChunkRow where
  hash : SqlarCasIndex.ChunkId
  ct   : ByteArray
  deriving Inhabited

opaque reassemble
    (caibx : Caibx)
    (fk    : FileKey)
    (payloadNonce : ByteArray)
    (fetch : SqlarCasIndex.ChunkId → Option ByteArray)
    : Option ByteArray

end SqlarCasSqlar
