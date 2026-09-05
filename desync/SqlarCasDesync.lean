import SqlarCasSqlar
import SqlarCasIndex

namespace SqlarCasDesync

open SqlarCasIndex

opaque chunkStorePath : ChunkId → String

def serve (row : SqlarCasSqlar.ChunkRow) : String × ByteArray :=
  (chunkStorePath row.hash, row.ct)

opaque parse : String → ByteArray → Option SqlarCasSqlar.ChunkRow

theorem serve_parse_roundtrip (row : SqlarCasSqlar.ChunkRow) :
    let (path, bytes) := serve row
    parse path bytes = some row := by
  sorry

end SqlarCasDesync
