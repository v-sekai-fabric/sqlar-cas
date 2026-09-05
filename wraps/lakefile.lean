import Lake
open Lake DSL

package «sqlar-cas-wraps» where
  -- Per-file DEK wrapped once per authorized principal. ReBAC decides who
  -- lives here at write time (in the caller); this layer only stores the wraps.

require «sqlar-cas-crypto» from ".." / "crypto"

@[default_target]
lean_lib SqlarCasWraps
