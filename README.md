Content-addressable chunk store using casync wire format inside SQLite, with age-style envelope encryption at the manifest layer and cross-realm chunk dedup.

## Layout — independent layers, one repo

Each layer is its own Lake project. `cd <layer> && lake build` builds it in isolation. Split-when-earned = `mv <layer>/ ../<new-repo>/` + change `require path` to `require git`.

    2-contract/sqlar-cas/
      bytes/       Parser foundation (Cursor, BE/LE readers)          — no deps
      hash/        SHA-512/256                                         — no deps
      zstd/        zstd encode / decode                                — no deps
      chunker/     Buzhash content-defined chunker                     — no deps
      index/       caibx wire format serialize / parse                 — no deps
      crypto/      AES-256-GCM + X25519 + ChaCha20-Poly1305 (libsodium)— no deps
      envelope/    Encrypted-caibx header + wrap / unwrap              — crypto
      sqlar/       sqlar + sqlar_chunks table shape, reassembler       — crypto envelope zstd hash chunker index
      wraps/       sqlar_dek_wraps + sqlar_principal_keys table shape  — crypto
      Theorems.lean  composition-root proofs across the 9 layers
      SqlarCas.lean  imports every layer
      lakefile.lean  requires every layer via `require path`
      lean-toolchain leanprover/lean4:v4.30.0 (matches fabric-store)

## Deployment cases

    live path (writers, private content):
      Godot / admin → Bao (ReBAC) → sqlite-fdb plugin → fabric-store → FDB → S3

    static path (readers, public content, GitHub Pages — Bao NOT required):
      Godot / browser → .sqlite file over HTTP (byte-range)
                      → chunks/<hex> over HTTP  (immutable, cache-perfect)
                      → age-x25519 private key held client-side unwraps DEK
                      → DEK decrypts caibx  → fetched chunks reassemble

The static case must survive OpenBao being gone. The design does: `wrapAlg = "age-x25519"` wraps carry an ephemeral X25519 public key + ChaCha20-Poly1305-sealed DEK; the recipient's private key unwraps locally. No online authority. The `sqlar_dek_wraps` table travels with the .sqlite file; the private key lives with the reader (Godot file, browser IndexedDB).

## Wire format

**Chunks (`sqlar_chunks`):** casync `.cacnk` verbatim — `SHA-512/256(uncompressed)` as chunk id, zstd-compressed bytes on disk. Buzhash CDC, 16 KiB / 256 KiB bounds. Constants preserved for Go desync interop (`CA_FORMAT_INDEX = 0x96824d9c7b129ff9` etc.).

**Manifests (`sqlar.data`):** `[version:1][alg:1][dek_id:16][nonce:12][AES-256-GCM(dek, caibx) || 16B tag]`.

**Wraps (`sqlar_dek_wraps.wrapped_dek`):** age-style — `[ephemeral_pub:32][nonce:12][ChaCha20-Poly1305(dek) || 16B tag]`. Written per authorized principal by the caller (Bao plugin uses ReBAC to enumerate recipients at write time).

## Spec-first discipline

Every theorem in `Theorems.lean` is stated before its C implementation ships. Proofs start `sorry`; a follow-up closes each. C cites the Lean spec, never the other way around.

Theorem list (all in `Theorems.lean`, all currently `sorry` except `chunker_deterministic`):

- `chunker_deterministic` (proved by `rfl`)
- `chunk_size_bounds`
- `reassemble_roundtrip`
- `content_addressable`
- `index_wire_magic`
- `sqlar_no_compression`
- `sqlar_chunk_roundtrip`
- `envelope_roundtrip`
- `wrap_roundtrip`
- `access_is_wrap_set`
- **`bao_absent_selfcontained`** — the "OpenBao can disappear" invariant for the static case

## Licence

Dual-licensed under Apache 2.0 or MIT.

`SPDX-License-Identifier: Apache-2.0 OR MIT`
