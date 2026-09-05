namespace SqlarCasIndex

/-- casync `.caibx` magic — first 8 bytes of every index, little-endian. -/
def CA_FORMAT_INDEX             : UInt64 := 0x96824d9c7b129ff9

/-- Table section marker. -/
def CA_FORMAT_TABLE             : UInt64 := 0xe75b9e112f17417d

/-- Table tail marker. -/
def CA_FORMAT_TABLE_TAIL_MARKER : UInt64 := 0x4b4f050e5549ecd1

/-- Hash algorithm flag: SHA-512/256. -/
def CA_FORMAT_SHA512_256        : UInt64 := 0x2000000000000000

/-- Table entry stride (id 32B + offset 8B + size 8B = 48B). -/
def CA_FORMAT_INDEX_SIZE        : UInt64 := 48

/-- 32-byte chunk id (structurally equal to any other `ByteArray` id in a peer layer). -/
abbrev ChunkId := ByteArray

/-- One entry in a caibx: chunk id + offset + size (uncompressed). -/
structure Entry where
  id     : ChunkId
  offset : UInt64
  size   : UInt64
  deriving Repr, Inhabited

/-- In-memory caibx. -/
abbrev Caibx := Array Entry

/-- Serialise `(id, raw_size)` pairs into the caibx wire format. -/
opaque build : Array (ChunkId × UInt64) → ByteArray

/-- Parse a caibx blob into entries. `none` on malformed input. -/
opaque parse : ByteArray → Option Caibx

end SqlarCasIndex
