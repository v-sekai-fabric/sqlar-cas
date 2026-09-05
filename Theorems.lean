import SqlarCasBytes
import SqlarCasHash
import SqlarCasZstd
import SqlarCasChunker
import SqlarCasIndex
import SqlarCasCrypto
import SqlarCasEnvelope
import SqlarCasSqlar
import SqlarCasWraps

/-!
# Composition-root theorems

Sqlar-cas splits into nine layers, each a Lake project one directory
deep. The layers are independently buildable — `cd <layer> && lake
build` — and the theorems below live at the composition root because
they name symbols from more than one layer at once.

`SqlarCasBytes` gives a `Cursor` and the primitive reads it advances.
`SqlarCasHash` gives `sha512_256`. `SqlarCasZstd` gives `encode` and
`decode`. `SqlarCasChunker` gives Buzhash content-defined chunking at
casync's bounds — `CHUNK_MIN_BYTES` through `CHUNK_MAX_BYTES`.
`SqlarCasIndex` gives the caibx wire — magic bytes, entry stride,
build/parse. Together they form the byte-level substrate every
higher layer speaks over.

`SqlarCasCrypto` gives the age v1.1.0 primitives (c2sp.org/age@v1.1.0):
`hkdfSha256`, `hmacSha256`, `chacha20Poly1305Encrypt` /
`Decrypt`, `x25519`, and the derived subkeys `payloadKey`, `macKey`,
`x25519WrapKey`, along with the wrap/unwrap primitives. Every crypto
choice here is age v1.1.0 to the letter.

`SqlarCasEnvelope` gives `Header` + `wrapCaibx` / `unwrapCaibx`,
computing header bytes as `encodeHeader h ++ name.toUTF8` so row
identity is bound into whatever AEAD the version byte selects.

`SqlarCasWraps` gives `Row` + `PrincipalKey`. One wrap construction
(age X25519), one row shape.

`SqlarCasSqlar` gives `Row` + `ChunkRow` + `reassemble` — the
top-level sqlar row and the content-addressed chunk row a reassembler
walks.

## The theorems, and what they say

The proofs are `sorry` today. The wire and threat shapes are stable
enough to reference; the proofs are not. Every theorem below states
what a follow-up must close — one theorem, one follow-up commit.
-/

namespace Theorems

open SqlarCasChunker SqlarCasHash SqlarCasZstd SqlarCasIndex
open SqlarCasCrypto SqlarCasEnvelope SqlarCasSqlar SqlarCasWraps

/-!
### Chunker

The chunker is a pure function of its input, so re-running it on the
same bytes yields the same array; this is the one theorem that closes
by `rfl` today.
-/

theorem chunker_deterministic (bs : ByteArray) : chunk bs = chunk bs := rfl

/-!
Every non-last chunk sits within casync's bounds. The last chunk may
be smaller because the tail of the file is what remains after the
Buzhash discriminator has stopped triggering.
-/

theorem chunk_size_bounds (bs : ByteArray) :
    ∀ i (h : i + 1 < (chunk bs).size),
      let c := (chunk bs)[i]'(Nat.lt_of_succ_lt h)
      CHUNK_MIN_BYTES ≤ c.raw.size ∧ c.raw.size ≤ CHUNK_MAX_BYTES := by
  sorry

/-!
### Reassembly

Given the plaintext bytes, chunk it, index each chunk by
`sha512_256`, build the caibx, and reassemble via a fetcher that
resolves ids back to the raw chunk bytes: the reassembler returns the
plaintext. The reassembler is payload-key-parameterised (age STREAM
on the emit side), so the roundtrip carries `fk` and `payloadNonce`
through, and a full proof wires STREAM-encrypt on the fetch side.
-/

theorem reassemble_roundtrip
    (bs : ByteArray) (fk : FileKey) (pn : ByteArray) :
    let cs := chunk bs
    let entries : Array (SqlarCasIndex.ChunkId × UInt64) :=
      cs.map (fun c => (sha512_256 c.raw, c.raw.size.toUInt64))
    let caibx := build entries
    let fetch : SqlarCasIndex.ChunkId → Option ByteArray :=
      fun id => (cs.find? (fun c => sha512_256 c.raw = id)).map (·.raw)
    reassemble ((parse caibx).getD #[]) fk pn fetch = some bs := by
  sorry

/-!
### Hash and index

Same chunk id implies same raw bytes — SHA-512/256 is collision-free
on our domain by assumption. Every valid caibx starts with
`CA_FORMAT_INDEX` in the first eight bytes.
-/

theorem content_addressable (a b : ByteArray) :
    sha512_256 a = sha512_256 b → a = b := by
  sorry

theorem index_wire_magic (entries : Array (SqlarCasIndex.ChunkId × UInt64)) :
    let caibx := build entries
    (parse caibx).isSome → caibx.size ≥ 8 := by
  sorry

/-!
### Sqlar rows and chunks

`sqlar.sz > sqlar.data.size` — the reassembled plaintext is always
larger than the envelope, which rules out an sqlar-native zlib path.
Chunk-row hash addresses the ciphertext bytes as they sit in
`sqlar_chunks.ct`.
-/

theorem sqlar_no_compression (row : SqlarCasSqlar.Row) :
    row.sz.toNat > row.data.size := by
  sorry

theorem sqlar_chunk_roundtrip (row : ChunkRow) :
    sha512_256 row.ct = row.hash := by
  sorry

/-!
### Envelope and wrap roundtrips

Encrypting a caibx under a fresh file_key + dek_id and decrypting
under the same file_key and row name recovers the caibx. Wrapping a
file_key to a recipient's X25519 public key and unwrapping with the
matching private key recovers the file_key.
-/

theorem envelope_roundtrip (caibx : ByteArray) (name : String) :
    let ⟨fk, _dekId, blob⟩ := wrapCaibx caibx name
    unwrapCaibx fk blob name = some caibx := by
  sorry

theorem wrap_roundtrip (fk : FileKey) (pub : X25519Pub) (priv : X25519Priv) :
    unwrapX25519 priv (wrapX25519 pub fk) = some fk := by
  sorry

/-!
### Access is exactly the wrap set

Sqlar-cas does not decide access. ReBAC decides who lives in
`sqlar_dek_wraps` at write time — the caller inserts wraps for the
principals a Bao decision covers. This theorem says: unwrapping
succeeds if-and-only-if the principal holds a wrap whose file_key
also unwraps the row's envelope. No third gate, no ambient authority.
-/

theorem access_is_wrap_set
    (row : SqlarCasSqlar.Row) (wraps : Array SqlarCasWraps.Row)
    (principal : String) (priv : X25519Priv) :
    (∃ w ∈ wraps,
       w.dekId = row.dekId ∧ w.principalId = principal
       ∧ (unwrapX25519 priv (w.ephemeralPub ++ w.wrappedKey)).isSome)
    ↔ (∃ fk w, w ∈ wraps
         ∧ w.dekId = row.dekId ∧ w.principalId = principal
         ∧ unwrapX25519 priv (w.ephemeralPub ++ w.wrappedKey) = some fk
         ∧ (unwrapCaibx fk row.data row.name).isSome) := by
  sorry

/-!
### The Bao-can-disappear invariant

The static-hosting case: given the sqlite file (rows + chunks +
wraps) and a matching X25519 private key, the recipient decrypts with
no external service running. Bao gates the write path; nothing on the
read path needs it. This is the theorem that says so: any wrap whose
dek_id names the row's file_key, when unwrapped locally, yields a
file_key that decrypts the envelope.
-/

theorem bao_absent_selfcontained
    (row : SqlarCasSqlar.Row) (w : SqlarCasWraps.Row) (priv : X25519Priv) :
    w.dekId = row.dekId
    → ∀ fk, unwrapX25519 priv (w.ephemeralPub ++ w.wrappedKey) = some fk
    → (unwrapCaibx fk row.data row.name).isSome := by
  sorry

end Theorems
