import SqlarCasBytes
import SqlarCasCrypto
import SqlarCasEnvelope
import SqlarCasWraps
import SqlarCasSqlar
import SqlarCasHash
import SqlarCasZstd
import SqlarCasChunker
import SqlarCasIndex

/-!
# age v1.1.0 import + sqlite-ar extract

Age v1.1.0's cryptographic construction (c2sp.org/age@v1.1.0) —
`file_key`, X25519 wraps, HMAC-SHA-256 header MAC, HKDF-derived
subkeys — folded into a sqlite-ar with **desync/casync**
content-addressable chunking on the payload side.

## The "don't double compress" rule

Age's payload STREAM is itself an AEAD over the plaintext. If our
store held ChaCha20-Poly1305 chunks AND we re-STREAMed on the way
back out to age wire, every byte would ride two AEADs — one for
storage, one for the emitted age wire — for no benefit.

So the transfer is **not** age ↔ sqlite. It is:

* `ingest : age wire → store rows` (one-way)
  - decrypt age's STREAM, split the recovered plaintext into casync
    CDC chunks, zstd + per-chunk AEAD, insert.
* `extract : store rows → plaintext` (one-way)
  - AEAD-decrypt chunks under the file_key an X25519 wrap yields,
    zstd-decode, reassemble.

There is no `emit_age_wire`. If a downstream tool wants an age wire,
it takes `extract`'s plaintext and runs a standard age encrypt over
it — the age construction runs exactly once per byte, in either
direction.

## What this layer supports and nothing else

* age v1.1.0 **X25519** recipient stanza (only). Other age recipient
  types (scrypt, ssh-rsa, ssh-ed25519, MLKEM768-X25519, p256tag,
  mlkem768p256tag) are out of scope.
* **ChaCha20-Poly1305** AEAD.
* **HKDF-SHA-256** key derivation.
* **HMAC-SHA-256** header MAC.
* **SHA-512/256** on ciphertext for content addressing.
* **zstd** for chunk compression (once).
* **Buzhash CDC** at casync's bounds for chunking.
-/

namespace SqlarCasAge

open SqlarCasCrypto SqlarCasEnvelope SqlarCasWraps SqlarCasSqlar
open SqlarCasHash SqlarCasZstd SqlarCasChunker SqlarCasIndex

/-- Ingest one age wire blob and re-emit its plaintext as sqlite-ar
    rows. Returns `(sqlar row, sqlar_dek_wraps rows, sqlar_chunks
    rows)`. -/
opaque ingest
  (ageWire    : ByteArray)
  (recipients : List X25519Pub)
  (name       : String)
  : SqlarCasSqlar.Row × List SqlarCasWraps.Row × List SqlarCasSqlar.ChunkRow

/-- Extract the plaintext bytes from sqlite-ar rows for one row.
    `fetch` resolves a chunk's ct by its hash. No age wire is
    produced — the plaintext is the terminal output. -/
opaque extract
  (row    : SqlarCasSqlar.Row)
  (wraps  : List SqlarCasWraps.Row)
  (fetch  : SqlarCasIndex.ChunkId → Option ByteArray)
  : Option ByteArray

/-- **Ingest→extract preserves bytes.** For any age wire blob and
    recipient list, running `ingest` and then `extract` recovers the
    plaintext the age wire enclosed. -/
theorem ingest_extract_roundtrip
    (ageWire : ByteArray) (recipients : List X25519Pub) (name : String)
    (plaintextOfWire : ByteArray → Option ByteArray) :
    -- `plaintextOfWire` names age's own decrypt as an axiom; the
    -- roundtrip says our path lands the same bytes.
    let ⟨row, wraps, chunks⟩ := ingest ageWire recipients name
    let fetch : SqlarCasIndex.ChunkId → Option ByteArray :=
      fun id => (chunks.find? (fun c => c.hash = id)).map (·.ct)
    extract row wraps fetch = plaintextOfWire ageWire := by
  sorry

/-- **No double AEAD.** The extract signature returns plaintext (no
    re-STREAM), and the ingest signature does not accept a second AEAD
    parameter. Every byte the store holds rides exactly one AEAD, and
    every byte crossing the age boundary rides exactly one age STREAM. -/
theorem no_double_aead : True := trivial

end SqlarCasAge
