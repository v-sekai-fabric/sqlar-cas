import SqlarCasCrypto

namespace SqlarCasEnvelope

open SqlarCasCrypto

structure Header where
  version      : UInt8
  dekId        : DekId
  payloadNonce : ByteArray
  deriving Inhabited

opaque encodeHeader : Header → ByteArray
opaque parseHeader  : ByteArray → Option (Header × ByteArray)

def headerBytes (h : Header) (name : String) : ByteArray :=
  encodeHeader h ++ name.toUTF8

opaque wrapCaibx (caibx : ByteArray) (name : String)
    : FileKey × DekId × ByteArray

opaque unwrapCaibx (fk : FileKey) (sqlarData : ByteArray) (name : String)
    : Option ByteArray

end SqlarCasEnvelope
