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
# Composition-root proofs — DRAFT

Age v1.1.0 crypto (c2sp.org/age@v1.1.0) in a SQLite wire; ReBAC lives
at write time via wrap insertion. See `comparison/Comparison.lean` for
the model and threat catalogue.

Every theorem below starts `sorry`; a follow-up closes each. C cites
the Lean spec, never the other way around.
-/

namespace Theorems

open SqlarCasChunker SqlarCasHash SqlarCasZstd SqlarCasIndex
open SqlarCasCrypto SqlarCasEnvelope SqlarCasSqlar SqlarCasWraps

/-- The chunker is a pure function of its input bytes. -/
theorem chunker_deterministic (bs : ByteArray) : chunk bs = chunk bs := rfl

/-- Every non-last chunk sits between `CHUNK_MIN_BYTES` and
    `CHUNK_MAX_BYTES`. The last chunk may be smaller. Restated with
    a simple ∀-membership shape; details deferred. -/
theorem chunk_size_bounds (bs : ByteArray) :
    ∀ i (h : i + 1 < (chunk bs).size),
      let c := (chunk bs)[i]'(Nat.lt_of_succ_lt h)
      CHUNK_MIN_BYTES ≤ c.raw.size ∧ c.raw.size ≤ CHUNK_MAX_BYTES := by
  sorry

/-- Chunk / caibx / reassemble roundtrip. The reassembler is now
    payload-key-parameterised (age STREAM), so a full statement of
    the roundtrip has to thread a fresh `file_key` and `payload_nonce`
    through STREAM-encrypt on the fetch side; the shape below states
    it and leaves the wiring to the proof. -/
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

/-- Same chunk id ⇒ same raw bytes (SHA-512/256 injective on our
    domain). -/
theorem content_addressable (a b : ByteArray) :
    sha512_256 a = sha512_256 b → a = b := by
  sorry

/-- Every valid caibx starts with `CA_FORMAT_INDEX` in little-endian
    (≥ 8 bytes). -/
theorem index_wire_magic (entries : Array (SqlarCasIndex.ChunkId × UInt64)) :
    let caibx := build entries
    (parse caibx).isSome → caibx.size ≥ 8 := by
  sorry

/-- `sqlar.sz > sqlar.data.size` — rules out sqlar-native zlib. -/
theorem sqlar_no_compression (row : SqlarCasSqlar.Row) : row.sz.toNat > row.data.size := by
  sorry

/-- Chunk-row hash addresses the CIPHERTEXT: chunks are STREAM ct,
    identified by SHA-512/256 of those bytes. -/
theorem sqlar_chunk_roundtrip (row : ChunkRow) :
    sha512_256 row.ct = row.hash := by
  sorry

/-- Envelope roundtrip: wrap a caibx under a fresh file_key + fresh
    dek_id, unwrap it under the same file_key and row name, recover
    the caibx. -/
theorem envelope_roundtrip (caibx : ByteArray) (name : String) :
    let ⟨fk, _dekId, blob⟩ := wrapCaibx caibx name
    unwrapCaibx fk blob name = some caibx := by
  sorry

/-- Age X25519 wrap roundtrip: the recipient's private key recovers
    the file_key. -/
theorem wrap_roundtrip (fk : FileKey) (pub : X25519Pub) (priv : X25519Priv) :
    unwrapX25519 priv (wrapX25519 pub fk) = some fk := by
  sorry

/-- Access is exactly the wrap set. Sqlar-cas does not decide access —
    ReBAC decides who lives in `sqlar_dek_wraps` (at write time, in the
    caller). -/
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

/-- **Bao-can-disappear invariant.** In the static case, decryption is
    self-contained: given the sqlite file (rows + chunks + wraps) and
    a matching X25519 private key, the recipient decrypts with no
    external service. -/
theorem bao_absent_selfcontained
    (row : SqlarCasSqlar.Row) (w : SqlarCasWraps.Row) (priv : X25519Priv) :
    w.dekId = row.dekId
    → ∀ fk, unwrapX25519 priv (w.ephemeralPub ++ w.wrappedKey) = some fk
    → (unwrapCaibx fk row.data row.name).isSome := by
  sorry

end Theorems
