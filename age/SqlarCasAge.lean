import SqlarCasCrypto
import SqlarCasEnvelope
import SqlarCasWraps
import SqlarCasSqlar
import SqlarCasHash
import SqlarCasZstd
import SqlarCasChunker
import SqlarCasIndex

namespace SqlarCasAge

open SqlarCasCrypto SqlarCasEnvelope SqlarCasWraps SqlarCasSqlar
open SqlarCasHash SqlarCasZstd SqlarCasChunker SqlarCasIndex

opaque ingest
  (ageWire    : ByteArray)
  (recipients : List X25519Pub)
  (name       : String)
  : SqlarCasSqlar.Row × List SqlarCasWraps.Row × List SqlarCasSqlar.ChunkRow

opaque extract
  (row    : SqlarCasSqlar.Row)
  (wraps  : List SqlarCasWraps.Row)
  (fetch  : SqlarCasIndex.ChunkId → Option ByteArray)
  : Option ByteArray

theorem ingest_extract_roundtrip
    (ageWire : ByteArray) (recipients : List X25519Pub) (name : String)
    (plaintextOfWire : ByteArray → Option ByteArray) :
    let ⟨row, wraps, chunks⟩ := ingest ageWire recipients name
    let fetch : SqlarCasIndex.ChunkId → Option ByteArray :=
      fun id => (chunks.find? (fun c => c.hash = id)).map (·.ct)
    extract row wraps fetch = plaintextOfWire ageWire := by
  sorry

end SqlarCasAge
