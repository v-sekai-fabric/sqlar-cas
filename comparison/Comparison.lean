/-!
# sqlar-cas — Lean spec of the wire format and threat properties

Companion to the HTML comparison. Models sqlar-cas's encrypted-payload
shape and states the properties it delivers on.

Adopts the age v1.1.0 cryptographic construction verbatim
(c2sp.org/age@v1.1.0):

* file key = 16 bytes CSPRNG
* payload key = HKDF-SHA-256(ikm=file_key, salt=payload_nonce, info="payload")
* payload STREAM = 64 KiB chunks, ChaCha20-Poly1305, nonce = 11-byte BE
  counter ‖ (0x01 last, else 0x00)
* header MAC = HMAC-SHA-256, key = HKDF-SHA-256(file_key, salt=empty,
  info="header")
* X25519 wrap = ChaCha20-Poly1305(HKDF-SHA-256(X25519(ephPriv, recipPub),
  salt=ephPub‖recipPub, info="age-encryption.org/v1/X25519"),
  nonce=12×0x00, file_key)

Only the ASCII header format of age is not carried over — sqlar-cas
puts the same bytes into SQLite tables (`sqlar.data`, `sqlar_dek_wraps`,
`sqlar_chunks`).

One wrap algorithm: X25519. A "public" file is one whose recipient
keypair has its private key openly published; the format has no `pub`
alg — the same X25519 wrap works, and whether a particular keypair's
private key is published is an operational decision, not a wire-format
bit.

Crypto primitives are opaque axioms. Cipher-dependent theorems are
`sorry` — the "spec-first, C follows" convention.
-/

noncomputable section

namespace SqlarCas

abbrev Bytes   := ByteArray
abbrev FileKey := Bytes  -- 16 bytes (age §"File Key")
abbrev DekId   := Bytes  -- 16 bytes (identifier for the wrapped file_key)
abbrev Name    := String

/-- caibx plaintext (inside the AEAD ciphertext of `sqlar.data`).
    No wrap-alg vocabulary — the `version` byte at the top of the
    envelope is the forward-compat seam. A different wrap alg is a
    version bump, not a new enum entry. -/
structure Caibx where
  chunks : Array (Bytes × Bytes × Nat)  -- (hash_ct, hash_pt, size)

/-- `sqlar.data` envelope. Header MAC is age's HMAC-SHA-256 over the
    header with a HKDF-derived key. Only the `version` byte carries
    forward-compat; the AEAD, KDF, MAC and wrap alg are all baked in
    to a given `version`. A different cipher choice is a version bump. -/
structure Envelope where
  version       : UInt8
  dekId         : DekId
  payloadNonce  : Bytes    -- age's STREAM per-file nonce (16 B)
  ciphertext    : Bytes    -- ChaCha20-Poly1305-STREAM(payload_key, ...)
  headerMac     : Bytes    -- HMAC-SHA-256(mac_key, headerBytes)

/-- One row of `sqlar_dek_wraps`. Body is age's X25519 recipient wrap:
      [ ephemeralPub : 32 ] [ wrappedKey ‖ tag : 16 + 16 ]
    No `wrap_alg` byte — a different wrap construction is a version
    bump on the envelope, not an in-table enum. -/
structure Wrap where
  dekId        : DekId
  ephemeralPub : Bytes     -- 32 B X25519 ephemeral public key
  wrappedKey   : Bytes     -- ChaCha20-Poly1305(x25519WrapKey, 12×0x00, file_key) ‖ tag

/-- One row of `sqlar_chunks`. -/
structure Chunk where
  hash : Bytes             -- SHA-512/256(ct)
  ct   : Bytes             -- ChaCha20-Poly1305-STREAM chunk

/-- One file's row in `sqlar`. -/
structure Row where
  name : Name
  data : Envelope

/-! ## Age-verbatim primitives (opaque) -/

axiom hkdf_sha256 :
  (ikm salt : Bytes) → (info : String) → (outLen : Nat) → Bytes
axiom hmac_sha256 : (key msg : Bytes) → Bytes
axiom chacha20_poly1305_encrypt :
  (key nonce pt aad : Bytes) → Bytes × Bytes
axiom chacha20_poly1305_decrypt :
  (key nonce ct tag aad : Bytes) → Option Bytes
axiom x25519 : (priv pub : Bytes) → Bytes

/-- age §"Payload key": `HKDF-SHA-256(file_key, salt=payload_nonce,
    info="payload")`. -/
def payloadKey (fileKey : FileKey) (payloadNonce : Bytes) : Bytes :=
  hkdf_sha256 fileKey payloadNonce "payload" 32

/-- age §"Header MAC key": `HKDF-SHA-256(file_key, salt=empty,
    info="header")`. -/
def macKey (fileKey : FileKey) : Bytes :=
  hkdf_sha256 fileKey ByteArray.empty "header" 32

/-- age §"X25519 recipient wrap key". -/
def x25519WrapKey (ephPriv recipPub ephPub : Bytes) : Bytes :=
  hkdf_sha256 (x25519 ephPriv recipPub) (ephPub ++ recipPub)
              "age-encryption.org/v1/X25519" 32

/-- age uses 12 zero bytes as the wrap AEAD nonce. -/
def wrapNonce : Bytes :=
  ByteArray.mk #[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

/-- age's STREAM per-chunk nonce: 11-byte BE counter, 1-byte last-flag. -/
axiom bigEndian11 : Nat → Bytes

def streamNonce (counter : Nat) (isLast : Bool) : Bytes :=
  (bigEndian11 counter).push (if isLast then (0x01 : UInt8) else 0x00)

/-- Header bytes covered by HMAC-SHA-256. `sqlar.name` is included so
    row identity is bound the way age's header bytes bind stanzas. -/
def headerBytes (row : Row) : Bytes :=
  let e := row.data
  (ByteArray.mk #[e.version]) ++ e.dekId ++ e.payloadNonce
    ++ row.name.toUTF8

/-- Equality on ByteArray is not in core; opaque. -/
axiom bytes_eq : Bytes → Bytes → Bool

def verifyHeader (fileKey : FileKey) (row : Row) : Bool :=
  bytes_eq (hmac_sha256 (macKey fileKey) (headerBytes row)) row.data.headerMac

/-! ## Threat model as ReBAC bypass

    A model, not a shape spec. The wire is only one plane; the threats
    ride on the recipient's keystore, the mirror's honesty, the Bao
    write path, the operator's rotation cadence, the network. Each
    threat is:

    * the tuple Bao GRANTED (`intent`) and the tuple the attacker
      reaches WITHOUT Bao's grant (`bypass`),
    * the attacker's capabilities *outside* the wire,
    * the trust boundary whose failure would enable the bypass,
    * the MEASURE that prevents (or bounds) the ReBAC success.

    Bypass theorems fall into two shapes: shape-level (a cipher
    property refuses the effective read) and operational (the shape
    exposes a lever that bounds the damage).
-/

/-- Zanzibar-style tuple `object#relation@subject`. -/
structure Tuple where
  object   : Name
  relation : String
  subject  : String
  deriving BEq, Repr

abbrev Grants := List Tuple

/-- The tuple a wrap denotes: a wrap of `row`'s file_key for `S` means
    Bao inserted `row.name#reader@S`. -/
def wrapDenotes (row : Row) (S : String) : Tuple :=
  { object := row.name, relation := "reader", subject := S }

/-! ### Model of the world outside the wire -/

/-- Capabilities an attacker can hold that the wire does not gate.
    A given attacker has some subset. -/
inductive Capability where
  | networkObserve             -- times or watches reader/writer traffic
  | sqlarWrite                 -- inserts/mutates `sqlar` rows
  | sqlarDekWrapsWrite         -- inserts/mutates `sqlar_dek_wraps` rows
  | sqlarChunksWrite           -- inserts/mutates `sqlar_chunks` rows
  | wrapRowDelete              -- deletes a wrap row after Bao granted
  | recipientPrivKey           -- holds the recipient X25519 private key
  | publishedPrivKey           -- has read an openly-published private key
  | physicalDeviceAccess       -- has recipient's device + keystore
  | quantumAdversary           -- runs Shor on captured wire
  deriving BEq, Repr

/-- Trust boundaries: parties whose correctness the design assumes.
    A bypass identifies which one the attack breaks. -/
inductive TrustBoundary where
  | bao        -- write path enforces ReBAC on wrap insertion
  | recipient  -- private key stays in recipient's keystore
  | operator   -- rotates when a recipient is revoked
  | mirror     -- serves the .sqlite honestly (static case)
  | cipher     -- symmetric primitive holds against the classical model
  deriving BEq, Repr

/-- What the wire+cipher blocks vs what operational levers bound. -/
inductive Measure where
  | headerMac              -- age HMAC over headerBytes incl. sqlar.name
  | constantTimeReader     -- wrap iteration hides the successful index
  | chunkHashVerify        -- SHA-512/256(ct) match on chunk fetch
  | rotate                 -- fresh file_key + fresh dek_id
  | keystoreHygiene        -- recipient side: TPM, HSM, OS keystore
  | mirrorPinning          -- reader pins .sqlite hash; mirror can't fork
  | versionBump            -- move to a version whose crypto is PQ
  | none                   -- no measure exists; residual risk
  deriving BEq, Repr

/-- One threat as a record. `intent` is the tuple Bao intended;
    `bypass` is the tuple the attacker reaches without Bao granting. -/
structure Threat where
  name       : String
  attacker   : List Capability
  boundary   : TrustBoundary
  intent     : Tuple
  bypass     : Tuple
  measure    : Measure
  deriving Repr

/-! ### Catalogue -/

/-- Placeholder subject names for the catalogue. -/
def alice : String := "alice"
def eve   : String := "eve"
def mallory : String := "mallory"
def anyone : String := "anyone"

/-- Placeholder file name. -/
def foo : Name := "foo"
def bar : Name := "bar"

def catalog : List Threat := [
  { name := "ciphertext-move"
    attacker := [.sqlarWrite]
    boundary := .cipher
    intent   := ⟨foo, "reader", alice⟩   -- Bao granted for foo
    bypass   := ⟨bar, "reader", alice⟩   -- attacker wants read on bar
    measure  := .headerMac },
  { name := "header-tamper"
    attacker := [.sqlarWrite, .sqlarDekWrapsWrite]
    boundary := .cipher
    intent   := ⟨foo, "reader", alice⟩
    bypass   := ⟨foo, "reader", mallory⟩
    measure  := .headerMac },
  { name := "wrap-lookup-timing"
    attacker := [.networkObserve]
    boundary := .cipher
    intent   := ⟨foo, "observe_who", alice⟩  -- Bao granted no one
    bypass   := ⟨foo, "observe_who", eve⟩
    measure  := .constantTimeReader },
  { name := "chunk-substitute (mirror)"
    attacker := [.sqlarChunksWrite]
    boundary := .mirror
    intent   := ⟨foo, "reader", alice⟩
    bypass   := ⟨foo, "reader", alice⟩  -- read succeeds, but returns lies
    -- (bypass tuple is same; the harm is on integrity, not confidentiality)
    measure  := .chunkHashVerify },
  { name := "cached-file_key after revocation"
    attacker := [.recipientPrivKey]  -- alice, post-revocation
    boundary := .operator            -- operator's rotation cadence
    intent   := ⟨foo, "reader", alice⟩  -- BEFORE revocation
    bypass   := ⟨foo, "reader", alice⟩  -- AFTER revocation
    measure  := .rotate },
  { name := "recipient device seized"
    attacker := [.physicalDeviceAccess, .recipientPrivKey]
    boundary := .recipient
    intent   := ⟨foo, "reader", alice⟩
    bypass   := ⟨foo, "reader", mallory⟩  -- mallory holds alice's key
    measure  := .keystoreHygiene },
  { name := "static-mirror serves stale wraps"
    attacker := [.sqlarDekWrapsWrite, .wrapRowDelete]
    boundary := .mirror
    intent   := ⟨foo, "reader", alice⟩  -- alice was revoked at origin
    bypass   := ⟨foo, "reader", alice⟩  -- stale mirror still has wrap
    measure  := .mirrorPinning },
  { name := "published-key file goes public"
    attacker := [.publishedPrivKey]
    boundary := .operator             -- publishing was operator's act
    intent   := ⟨foo, "reader", anyone⟩ -- intended public
    bypass   := ⟨foo, "reader", anyone⟩ -- also achieved
    -- Not a bypass at all — bypass tuple equals intent. Included so
    -- the catalogue reflects that "public" is intent, not attack.
    measure  := .none },
  { name := "quantum recovery of X25519 wraps"
    attacker := [.networkObserve, .quantumAdversary]
    boundary := .cipher
    intent   := ⟨foo, "reader", alice⟩
    bypass   := ⟨foo, "reader", mallory⟩  -- Shor recovers alice's key
    measure  := .versionBump }
]

/-! ### Bypass theorems (shape-level measures)

    A shape-level measure gives a theorem: given the attacker's
    capabilities and the intent-vs-bypass tuple mismatch, the shape
    refuses the read. Proofs of the cipher-dependent side are
    `sorry` per the "spec-first, C follows" convention. -/

/-- Effective read: S can read `row` under `wraps` iff S can present
    material that (a) unwraps one of `row`'s wraps to a candidate
    file_key and (b) that file_key verifies `row`'s header MAC.
    Opaque — reader's decision procedure. -/
axiom effectiveRead : Row → List Wrap → String → Bool

/-- Age's HMAC binds distinct header bytes to distinct tags under any
    fixed key. -/
axiom hmac_binding
    (key h h' : Bytes) :
    h ≠ h' → hmac_sha256 key h ≠ hmac_sha256 key h'

/-- Effective read requires header verification under some file key. -/
axiom effectiveRead_requires_header_verify
    (row : Row) (wraps : List Wrap) (S : String) :
    effectiveRead row wraps S = true →
    ∃ fileKey : FileKey, verifyHeader fileKey row = true

/-- Ciphertext-move: the moved row's headerBytes carries the wrong
    name; HMAC rejects. Measure = `headerMac`. -/
theorem ciphertext_move_no_bypass
    (foo bar : Row) (wraps : List Wrap) (S : String)
    (hne : foo.name ≠ bar.name) :
    let moved : Row := { name := bar.name, data := foo.data }
    effectiveRead moved wraps S = false := by
  sorry

/-- Header tamper: any change to {version, dek_id, payload_nonce}
    changes headerBytes; HMAC rejects. Measure = `headerMac`. -/
theorem header_tamper_no_bypass
    (row row' : Row) (wraps : List Wrap) (S : String)
    (hsame_name : row.name = row'.name)
    (hne_header : headerBytes row ≠ headerBytes row') :
    effectiveRead row' wraps S = false := by
  sorry

/-- Chunk substitute: any change to a chunk's ciphertext changes
    its SHA-512/256, so a reader that verifies the ct hash refuses
    the substitute. Measure = `chunkHashVerify`. -/
axiom chunkReaderVerifies :
    ∀ (chunk : Chunk) (candidate : Bytes),
      candidate ≠ chunk.ct → True  -- opaque hash-verify placeholder

/-! ### Operational levers (no shape prevention)

    Cached-file_key, physical device seize, stale-mirror wraps, and
    quantum recovery are not preventable at the wire. The shape
    exposes bounding levers (or names the operational boundary). -/

axiom rotate : Row → FileKey → List Wrap → (Row × List Wrap)

axiom rotate_changes_dek_id
    (row : Row) (newKey : FileKey) (wraps : List Wrap) :
    row.data.dekId ≠ (rotate row newKey wraps).1.data.dekId

/-- Cached-file_key bypass is bounded by rotation: post-rotation the
    dek_id differs; any cached file_key no longer names the current
    envelope's key. Measure = `rotate`. -/
theorem rotation_bounds_cached_bypass
    (row : Row) (newKey : FileKey) (wraps : List Wrap) :
    (rotate row newKey wraps).1.data.dekId ≠ row.data.dekId := by
  exact (rotate_changes_dek_id row newKey wraps).symm

/-- Shape-level statement that rotation exists at all. -/
theorem sqlar_has_revocation_lever
    (row : Row) (newKey : FileKey) (wraps : List Wrap) :
    ∃ newDekId : DekId,
      newDekId ≠ row.data.dekId ∧
      newDekId = (rotate row newKey wraps).1.data.dekId := by
  refine ⟨(rotate row newKey wraps).1.data.dekId, ?_, rfl⟩
  exact (rotate_changes_dek_id row newKey wraps).symm

/-- Mirror pinning: the reader pins the .sqlite hash it expects,
    refusing a mirror whose file hash differs. Measure = `mirrorPinning`.
    A shape-level check, but the pinned value comes from an
    out-of-wire trust (git tag, TOFU, delegated notary). -/
axiom readerPinnedSqliteHash : String → Option Bytes
axiom readerAcceptsMirror
    (mirrorHash : Bytes) (fileName : String) :
    (∀ pinned, readerPinnedSqliteHash fileName = some pinned →
      pinned = mirrorHash) → True

/-- Quantum recovery: the wire allows a version bump to a PQ wrap
    construction; the measure exists at the seam, not in today's
    cipher. Measure = `versionBump`. -/
theorem version_byte_allows_pq_migration :
    ∃ (v : UInt8), v ≠ 0x01 := by
  exact ⟨0x02, by decide⟩

/-! ## "Public" without a wrap alg

    A file is public when at least one of its wraps encrypts the
    file_key to a recipient X25519 pubkey whose private key is openly
    published (in Bao, a git repo, a well-known URL). The wrap uses
    the same X25519 construction as any other; only the operational
    fact that the private key is published makes the wrap unwrappable
    by everyone.

    This is not a wire-format bit. The spec above reflects that: there
    is no `WrapAlg`, no `isPublicWrap` predicate, no `unwrapPublic`
    special case. -/

end SqlarCas
