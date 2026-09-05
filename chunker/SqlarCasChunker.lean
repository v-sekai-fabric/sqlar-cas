namespace SqlarCasChunker

/-- Buzhash rolling-window size (bytes). -/
def CHUNK_WINDOW    : Nat := 48

/-- Minimum chunk size (16 KiB). -/
def CHUNK_MIN_BYTES : Nat := 16 * 1024

/-- Maximum chunk size (256 KiB). -/
def CHUNK_MAX_BYTES : Nat := 256 * 1024

/-- Target average chunk size (64 KiB) — feeds the discriminator. -/
def CHUNK_AVG_BYTES : Nat := 64 * 1024

/-- One produced chunk: its raw bytes and the offset where it starts. The id is
    derived by the caller via `SqlarCasHash.sha512_256 raw`. -/
structure Chunk where
  raw    : ByteArray
  offset : UInt64
  deriving Inhabited

/-- Cut a byte array into chunks by the buzhash discriminator. Non-last chunks
    sit in `[CHUNK_MIN_BYTES, CHUNK_MAX_BYTES]`; the last chunk may be smaller. -/
opaque chunk : ByteArray → Array Chunk

end SqlarCasChunker
