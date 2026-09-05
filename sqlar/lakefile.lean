import Lake
open Lake DSL

package «sqlar-cas-sqlar» where
  -- sqlar table shape + reassembler. Depends on the crypto envelope for the
  -- `data` blob's shape, on chunker/hash/zstd/index for the reassemble path.

require «sqlar-cas-crypto»   from ".." / "crypto"
require «sqlar-cas-envelope» from ".." / "envelope"
require «sqlar-cas-zstd»     from ".." / "zstd"
require «sqlar-cas-hash»     from ".." / "hash"
require «sqlar-cas-chunker»  from ".." / "chunker"
require «sqlar-cas-index»    from ".." / "index"

@[default_target]
lean_lib SqlarCasSqlar
