namespace SqlarCasZstd

/-- zstd frame encode. -/
opaque encode : ByteArray → ByteArray

/-- zstd frame decode. `none` on malformed input. -/
opaque decode : ByteArray → Option ByteArray

end SqlarCasZstd
