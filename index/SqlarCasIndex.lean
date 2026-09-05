namespace SqlarCasIndex

def CA_FORMAT_INDEX             : UInt64 := 0x96824d9c7b129ff9
def CA_FORMAT_TABLE             : UInt64 := 0xe75b9e112f17417d
def CA_FORMAT_TABLE_TAIL_MARKER : UInt64 := 0x4b4f050e5549ecd1
def CA_FORMAT_SHA512_256        : UInt64 := 0x2000000000000000
def CA_FORMAT_INDEX_SIZE        : UInt64 := 48

abbrev ChunkId := ByteArray

structure Entry where
  id     : ChunkId
  offset : UInt64
  size   : UInt64
  deriving Inhabited

abbrev Caibx := Array Entry

opaque build : Array (ChunkId × UInt64) → ByteArray
opaque parse : ByteArray → Option Caibx

end SqlarCasIndex
