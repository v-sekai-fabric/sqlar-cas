import Lake
open Lake DSL

package «sqlar-cas» where
  -- Composition-root Lake project. Requires every layer via `require path` so
  -- each layer stays independently buildable (`cd <layer> && lake build`).
  -- Split-when-earned: `mv <layer>/ ../<new-repo>/` + change the corresponding
  -- `require path` below to `require git` — zero import churn.

require «sqlar-cas-bytes»    from "bytes"
require «sqlar-cas-hash»     from "hash"
require «sqlar-cas-zstd»     from "zstd"
require «sqlar-cas-chunker»  from "chunker"
require «sqlar-cas-index»    from "index"
require «sqlar-cas-crypto»   from "crypto"
require «sqlar-cas-envelope» from "envelope"
require «sqlar-cas-sqlar»    from "sqlar"
require «sqlar-cas-wraps»    from "wraps"

@[default_target]
lean_lib SqlarCas
