import Lake
open Lake DSL

package «sqlar-cas-desync» where

require «sqlar-cas-sqlar» from ".." / "sqlar"
require «sqlar-cas-index» from ".." / "index"

@[default_target]
lean_lib SqlarCasDesync
