namespace SqlarCasBytes

/-- Cursor into a byte array with a bounded read position. -/
structure Cursor where
  bytes : ByteArray
  pos   : Nat
  deriving Inhabited

/-- Read one little-endian `UInt64`. Advances the cursor. -/
opaque readU64LE : Cursor → Option (UInt64 × Cursor)

/-- Read one big-endian `UInt64`. -/
opaque readU64BE : Cursor → Option (UInt64 × Cursor)

/-- Read `n` raw bytes. Fails if the cursor overruns. -/
opaque readBytes : Cursor → Nat → Option (ByteArray × Cursor)

end SqlarCasBytes
