import Lake
open Lake DSL

package «sqlar-cas-crypto» where
  -- Bao-independent crypto primitives: AES-256-GCM (caibx cipher),
  -- X25519 + ChaCha20-Poly1305 (age-style DEK wrap), HKDF-SHA-256 (key derive
  -- from ECDH shared secret). Reference backend is libsodium. Nothing here
  -- talks to any external service — required for the "OpenBao can disappear"
  -- static / GitHub Pages case.

@[default_target]
lean_lib SqlarCasCrypto
