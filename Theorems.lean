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
# Composition-root proofs

The sorry-free theorems span the 9 layer libraries. Each starts as `sorry`;
follow-up PRs close them one at a time.
-/

namespace Theorems

open SqlarCasChunker SqlarCasHash SqlarCasZstd SqlarCasIndex
open SqlarCasCrypto SqlarCasEnvelope SqlarCasSqlar SqlarCasWraps

/-- The chunker is a pure function of its input bytes. -/
theorem chunker_deterministic (bs : ByteArray) : chunk bs = chunk bs := rfl

/-- Every non-last chunk sits between `CHUNK_MIN_BYTES` and `CHUNK_MAX_BYTES`.
    The last chunk may be smaller. -/
theorem chunk_size_bounds (bs : ByteArray) :
    ∀ i, (h : i + 1 < (chunk bs).size) →
      CHUNK_MIN_BYTES ≤ (chunk bs)[i]'(Nat.lt_of_succ_lt h)|>.raw.size
      ∧ (chunk bs)[i]'(Nat.lt_of_succ_lt h)|>.raw.size ≤ CHUNK_MAX_BYTES := by
  sorry

/-- Chunk any byte array, serialise the caibx, then reassemble: recover the input. -/
theorem reassemble_roundtrip (bs : ByteArray) :
    let cs := chunk bs
    let entries : Array (ChunkId × UInt64) :=
      cs.map (fun c => (sha512_256 c.raw, c.raw.size.toUInt64))
    let caibx := build entries
    let lookup : ChunkId → Option ByteArray :=
      fun id => (cs.find? (fun c => sha512_256 c.raw = id)).map (·.raw)
    reassemble ((parse caibx).getD #[]) lookup = some bs := by
  sorry

/-- Same chunk id ⇒ same raw bytes (SHA-512/256 injective on our domain). -/
theorem content_addressable (a b : ByteArray) :
    sha512_256 a = sha512_256 b → a = b := by
  sorry

/-- Every valid caibx starts with `CA_FORMAT_INDEX` in little-endian (≥ 8 bytes). -/
theorem index_wire_magic (entries : Array (ChunkId × UInt64)) :
    let caibx := build entries
    (parse caibx).isSome → caibx.size ≥ 8 := by
  sorry

/-- `sqlar.sz > sqlar.data.size` — rules out sqlar-native zlib. -/
theorem sqlar_no_compression (row : Row) : row.sz.toNat > row.data.size := by
  sorry

/-- Chunk-row roundtrip: zstd-decode and the hash matches. -/
theorem sqlar_chunk_roundtrip (row : ChunkRow) :
    ∀ raw, decode row.data = some raw → sha512_256 raw = row.hash := by
  sorry

/-- Envelope roundtrip: `unwrapCaibx dek (wrapCaibx caibx).2.2 = some caibx`. -/
theorem envelope_roundtrip (caibx : ByteArray) :
    let ⟨dek, _dekId, blob⟩ := wrapCaibx caibx
    unwrapCaibx dek blob = some caibx := by
  sorry

/-- age-wrap roundtrip: unwrap with the recipient's private key recovers the DEK. -/
theorem wrap_roundtrip (dek : DEK) (pub : X25519Pub) (priv : X25519Priv) :
    -- The X25519 keypair relation is a crypto-backend axiom; stated abstractly.
    unwrapAge priv (wrapAge pub dek) = some dek := by
  sorry

/-- Access is exactly the wrap set. Sqlar-cas does not decide access — ReBAC
    decides who lives in `sqlar_dek_wraps` (at write time, in the caller). -/
theorem access_is_wrap_set
    (row : Row) (wraps : Array SqlarCasWraps.Row)
    (principal : String) (priv : X25519Priv) :
    (∃ w ∈ wraps, w.dekId = row.dekId ∧ w.principalId = principal
       ∧ (unwrapAge priv w.wrappedDek).isSome)
    ↔ (∃ dek w, w ∈ wraps ∧ w.dekId = row.dekId ∧ w.principalId = principal
         ∧ unwrapAge priv w.wrappedDek = some dek
         ∧ (unwrapCaibx dek row.data).isSome) := by
  sorry

/-- **OpenBao-can-disappear invariant.** In the static / GitHub Pages case,
    decryption is self-contained: given the sqlite file (rows + chunks + wraps)
    and a matching age-x25519 private key, the recipient decrypts with no
    external service. Reads: for any age-x25519 wrap that unwraps for `priv`,
    the DEK it yields decrypts `row.data`. -/
theorem bao_absent_selfcontained
    (row : Row) (w : SqlarCasWraps.Row) (priv : X25519Priv) :
    w.dekId = row.dekId
    → w.wrapAlg = "age-x25519"
    → ∀ dek, unwrapAge priv w.wrappedDek = some dek
    → (unwrapCaibx dek row.data).isSome := by
  sorry

end Theorems
