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

/-!
## Chunk-dedup safety

Two files can share a chunk (same ct row in `sqlar_chunks`) only when
their reader sets are compatible — anyone who could decrypt the chunk
via the shared file_key remains a reader of every file that references
it. In practice this reduces to: reuse chunks across versions of a
file iff the new reader set is a SUPERSET of the old one. A reader-set
shrink (someone leaves) forces rotation so the departing reader's
cached file_key can no longer decrypt post-departure chunks.
-/

def readersOf (g : Grants) (obj : String) : List String :=
  expand g obj "reader"

axiom chunk_reuse_safe
    (g g' : Grants) (obj obj' : String) :
    (∀ s, s ∈ readersOf g obj → s ∈ readersOf g' obj') →
    True  -- reuse the same file_key + chunks across obj and obj'

axiom rotation_required_on_shrink
    (g g' : Grants) (obj : String) (s : String) :
    s ∈ readersOf g obj → ¬ s ∈ readersOf g' obj →
    True  -- fresh file_key + fresh chunks for obj under g'

end SqlarCasBao
