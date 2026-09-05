# sqlar-cas

**Draft.** Content-addressable chunk store: casync wire in SQLite, [age v1.1.0](https://c2sp.org/age@v1.1.0) crypto, ReBAC via wraps.

Nothing here is a stable interface yet — the wire format is still moving, and no reference implementation ships. The spec is the source of truth; the C follows.

## Where the spec lives

- `comparison/Comparison.lean` — top-level Lean model: envelope, wraps, chunks, and the ReBAC threat model with per-threat measures. Compiles standalone (`cd comparison && lake build`).
- `Theorems.lean` — composition-root theorems across the layer libs (`sorry` where cipher-dependent, per the "spec-first, C follows" discipline).
- Layer directories carry their own docstrings; crypto and byte-layout details live at those docstrings and at `Comparison.lean`, not in this README.

## Layout — independent layers, one repo

Each layer is its own Lake project. `cd <layer> && lake build` builds it in isolation. Split-when-earned = `mv <layer>/ ../<new-repo>/` + change the corresponding `require path` in the top-level `lakefile.lean` to `require git`.

    2-contract/sqlar-cas/
      bytes/       Parser foundation (Cursor, BE/LE readers)
      hash/        SHA-512/256
      zstd/        zstd encode / decode
      chunker/     Buzhash content-defined chunker
      index/       caibx wire format serialize / parse
      crypto/      Age v1.1.0 primitives (HKDF / HMAC / ChaCha20-Poly1305 / X25519)
      envelope/    sqlar.data header + wrap / unwrap caibx
      sqlar/       sqlar + sqlar_chunks tables, reassembler
      wraps/       sqlar_dek_wraps + sqlar_principal_keys
      comparison/  Top-level Lean spec + ReBAC threat model
      Theorems.lean  Composition-root proofs across the 9 layers
      SqlarCas.lean  Imports every layer
      lakefile.lean  Requires every layer via `require path`

## Licence

Dual-licensed under Apache 2.0 or MIT.

`SPDX-License-Identifier: Apache-2.0 OR MIT`
