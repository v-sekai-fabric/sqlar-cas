import Lake
open Lake DSL

package «sqlar-cas-age» where

require «sqlar-cas-bytes»    from ".." / "bytes"
require «sqlar-cas-crypto»   from ".." / "crypto"
require «sqlar-cas-envelope» from ".." / "envelope"
require «sqlar-cas-wraps»    from ".." / "wraps"
require «sqlar-cas-sqlar»    from ".." / "sqlar"
require «sqlar-cas-hash»     from ".." / "hash"
require «sqlar-cas-zstd»     from ".." / "zstd"
require «sqlar-cas-chunker»  from ".." / "chunker"
require «sqlar-cas-index»    from ".." / "index"

@[default_target]
lean_lib SqlarCasAge
