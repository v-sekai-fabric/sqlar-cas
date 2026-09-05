namespace SqlarCasBao

/-!
Zanzibar-style ReBAC. A `Tuple` is `(object, relation, userset)`.
A userset is either a plain subject or `object#relation` (a computed
userset). `expand` resolves recursively with a cycle guard. The
store's wrap-set is a rebase on top of the file_key + chunk base:
`grant` = commit, `revoke` = revert, recursive relations let a group
change ripple to every object whose readers are that group#member.
-/

structure Tuple where
  object   : String
  relation : String
  userset  : String
  deriving BEq, Repr

abbrev Grants := List Tuple

opaque expand : Grants → String → String → List String

axiom expand_direct
    (g : Grants) (o r s : String) :
    ⟨o, r, s⟩ ∈ g → ¬ String.contains s '#' → s ∈ expand g o r

axiom expand_computed
    (g : Grants) (o r o' r' s : String) :
    ⟨o, r, o' ++ "#" ++ r'⟩ ∈ g → s ∈ expand g o' r' → s ∈ expand g o r

axiom expand_terminates
    (g : Grants) (o r : String) :
    (expand g o r).length ≤ g.length + 1

opaque authorizeWriteWrap : Grants → String → String → Bool

axiom authorize_iff_expanded
    (g : Grants) (subject obj : String) :
    authorizeWriteWrap g subject obj = true ↔
      subject ∈ expand g obj "reader"

opaque enumerateRecipients : Grants → String → List String

axiom enumerate_is_expand
    (g : Grants) (obj s : String) :
    s ∈ enumerateRecipients g obj ↔
      s ∈ expand g obj "reader"

end SqlarCasBao
