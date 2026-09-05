import Lake
open Lake DSL

package «sqlar-cas-chunker» where
  -- buzhash content-defined chunker. Own types; depends on nothing so it can
  -- ship on its own once the layer is stable.

@[default_target]
lean_lib SqlarCasChunker
