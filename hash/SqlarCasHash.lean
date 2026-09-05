namespace SqlarCasHash

/-- 32-byte SHA-512/256 chunk identifier. -/
abbrev ChunkId := ByteArray

/-- SHA-512/256 (FIPS 180-4 §5.3.6.2). 32 bytes out. -/
opaque sha512_256 : ByteArray → ChunkId

end SqlarCasHash
