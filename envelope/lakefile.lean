import Lake
open Lake DSL

package «sqlar-cas-envelope» where
  -- caibx envelope: on-disk header + AEAD-wrapped caibx bytes.
  -- Depends on `sqlar-cas-crypto` for the underlying AEAD.

require «sqlar-cas-crypto» from ".." / "crypto"

@[default_target]
lean_lib SqlarCasEnvelope
