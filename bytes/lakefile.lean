import Lake
open Lake DSL

package «sqlar-cas-bytes» where
  -- Parser foundation: little-endian / big-endian readers, cursor, ByteArray
  -- helpers. Depends on nothing.

@[default_target]
lean_lib SqlarCasBytes
