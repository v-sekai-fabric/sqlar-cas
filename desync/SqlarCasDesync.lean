import SqlarCasSqlar
import SqlarCasIndex

/-!
# `sqlar_chunks` served through desync

[desync](https://github.com/folbricht/desync) is the Go casync-compat
tool. It speaks casync content-addressable stores over HTTP, S3, and
local filesystems, addressed by `<hex-hash>.cacnk` with a two-level
directory split — the first 4 hex chars form the outer directory, then
the full hash names the file.

Because `sqlar_chunks.ct` is already ChaCha20-Poly1305-STREAM ct
(bytes on the wire), and `sqlar_chunks.hash` is already
SHA-512/256(ct), our chunk store IS a desync chunk store — we just
name the rows the way desync expects.

The core of this layer is the naming function; the wire beyond that
is desync's own protocol, not ours.
-/

namespace SqlarCasDesync

open SqlarCasIndex

/-- Format a chunk hash into desync's `<outer>/<hash>.cacnk` layout.
    `outer` = first 4 hex chars; `<hash>` = the full 64-char hex. -/
opaque chunkStorePath (id : ChunkId) : String

/-- Given a `sqlar_chunks` row, the tuple `(path, bytes)` a desync
    store would serve for that chunk. Both directions of a mirror
    (populate the desync store from sqlar_chunks; hydrate sqlar_chunks
    from a desync store) fall out of this one function. -/
def serve (row : SqlarCasSqlar.ChunkRow) : String × ByteArray :=
  (chunkStorePath row.hash, row.ct)

/-- The reverse: given a desync-format `(path, bytes)`, recover the
    `sqlar_chunks` row that produced it. `none` if `path` isn't the
    expected shape or if `SHA-512/256(bytes)` doesn't match the hash
    the path encodes. Verification is deferred (a hash-layer check). -/
opaque parse (path : String) (bytes : ByteArray) : Option SqlarCasSqlar.ChunkRow

/-- **Bidirectionality.** For any well-formed `sqlar_chunks` row, the
    serve→parse roundtrip recovers the same row. -/
theorem serve_parse_roundtrip (row : SqlarCasSqlar.ChunkRow) :
    let (path, bytes) := serve row
    parse path bytes = some row := by
  sorry

end SqlarCasDesync
