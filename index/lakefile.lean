import Lake
open Lake DSL

package «sqlar-cas-index» where
  -- caibx (chunk-index) wire-format serialize / parse. Casync magics preserved
  -- verbatim for Go desync interop. Depends on nothing.

@[default_target]
lean_lib SqlarCasIndex
