namespace SqlarCasBytes

structure Cursor where
  bytes : ByteArray
  pos   : Nat
  deriving Inhabited

opaque readU64LE : Cursor → Option (UInt64 × Cursor)
opaque readU64BE : Cursor → Option (UInt64 × Cursor)
opaque readBytes : Cursor → Nat → Option (ByteArray × Cursor)

end SqlarCasBytes
