namespace SqlarCasChunker

def CHUNK_WINDOW    : Nat := 48
def CHUNK_MIN_BYTES : Nat := 16 * 1024
def CHUNK_MAX_BYTES : Nat := 256 * 1024
def CHUNK_AVG_BYTES : Nat := 64 * 1024

structure Chunk where
  raw    : ByteArray
  offset : UInt64
  deriving Inhabited

opaque chunk : ByteArray → Array Chunk

end SqlarCasChunker
