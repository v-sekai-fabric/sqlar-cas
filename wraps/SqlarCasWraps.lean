import SqlarCasCrypto

namespace SqlarCasWraps

open SqlarCasCrypto

/-- One row of the `sqlar_dek_wraps` table: a DEK wrapped for a single principal. -/
structure Row where
  dekId       : DekId
  principalId : String
  wrappedDek  : ByteArray
  wrapAlg     : String       -- "age-x25519" (static-Pages friendly)
                             -- | "aes-kek-gcm" (out-of-band shared symmetric KEK)
                             -- | "bao-transit-<mount>" (live-only; unusable when Bao is gone)
  grantedAt   : Int64
  grantedBy   : String
  deriving Repr, Inhabited

/-- One row of the `sqlar_principal_keys` table (public halves; private halves
    stay client-side). -/
structure PrincipalKey where
  principalId : String
  wrapAlg     : String
  publicKey   : X25519Pub
  deriving Repr, Inhabited

end SqlarCasWraps
