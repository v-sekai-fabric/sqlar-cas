import SqlarCasCrypto

namespace SqlarCasWraps

open SqlarCasCrypto

structure Row where
  dekId        : DekId
  principalId  : String
  ephemeralPub : X25519Pub
  wrappedKey   : ByteArray
  grantedAt    : Int64
  grantedBy    : String
  deriving Inhabited

structure PrincipalKey where
  principalId : String
  publicKey   : X25519Pub
  deriving Inhabited

end SqlarCasWraps
