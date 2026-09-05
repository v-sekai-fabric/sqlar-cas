namespace SqlarCasBao

structure Tuple where
  subject  : String
  object   : String
  relation : String
  deriving BEq, Repr

abbrev Grants := List Tuple

opaque authorizeWriteWrap : Grants → String → String → Bool
opaque enumerateRecipients : Grants → String → List String

axiom authorize_iff_granted
    (g : Grants) (subject obj : String) :
    authorizeWriteWrap g subject obj = true ↔
      ⟨subject, obj, "reader"⟩ ∈ g

axiom enumerate_lists_readers
    (g : Grants) (obj s : String) :
    s ∈ enumerateRecipients g obj ↔
      ⟨s, obj, "reader"⟩ ∈ g

end SqlarCasBao
