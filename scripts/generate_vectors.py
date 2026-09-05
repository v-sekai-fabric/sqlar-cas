#!/usr/bin/env python3
"""Generate sqlar-cas test vectors under testdata/.

Vector format (matches CCTV shape): text header + blank line + raw
SQLite blob body. The blob contains the sqlar / sqlar_dek_wraps /
sqlar_chunks tables populated for that vector.
"""

import hashlib
import os
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from sqlar_cas_py import (  # noqa: E402
    Bao, build_sqlite, ingest_plaintext, priv_to_bytes, pub_to_bytes,
    write_chunks_to_store,
)

REPO = HERE.parent
OUT = REPO / "testdata"
CHUNK_STORE = OUT / "chunks"


def gen_recipients(n):
    out = []
    for _ in range(n):
        priv = X25519PrivateKey.generate()
        out.append((priv, priv.public_key()))
    return out


def vector(name, plaintext, num_recipients, recipients=None,
           file_key=None, dek_id=None, payload_nonce=None):
    if recipients is None:
        recipients = gen_recipients(num_recipients)
    pubs = [pub_to_bytes(p) for _, p in recipients]
    ing = ingest_plaintext(
        plaintext, name, pubs,
        file_key=file_key, dek_id=dek_id, payload_nonce=payload_nonce,
    )
    write_chunks_to_store(ing["chunks"], CHUNK_STORE)
    sqlite_blob = build_sqlite(name, ing, embed_chunks=False)

    header = [
        "expect: success",
        f"name: {name}",
        f"file_key: {ing['file_key'].hex()}",
        f"dek_id: {ing['dek_id'].hex()}",
        f"payload_nonce: {ing['payload_nonce'].hex()}",
        f"payload_sha256: {hashlib.sha256(plaintext).hexdigest()}",
        f"payload_size: {len(plaintext)}",
        f"num_recipients: {num_recipients}",
        f"num_chunks: {len(ing['chunks'])}",
    ]
    for i, (priv, pub) in enumerate(recipients):
        header.append(f"recipient_pub_{i}: {pub_to_bytes(pub).hex()}")
        header.append(f"recipient_priv_{i}: {priv_to_bytes(priv).hex()}")

    body = sqlite_blob
    return b"\n".join(l.encode() for l in header) + b"\n\n" + body


def gen_joined_world():
    """Three vectors evolving the friends group.

    Chunk dedup is only safe when the new reader set is a SUPERSET of
    the old one — anyone with a cached file_key from the old state
    still holds a valid key, so we cannot let a chunk they could
    decrypt end up on a file they no longer read.

    * v0 (alice, bob, charlie)   -- fresh file_key/dek_id/nonce
    * v1 (v0 + dave)             -- readers grew, REUSE v0's base
    * v2 (v1 - alice)            -- readers shrank, ROTATE to fresh
      base so alice's cached key can't decrypt v2's chunks

    Returns [(name, recipients, file_key, dek_id, payload_nonce)]. -/
    """
    world_content = os.urandom(1024 * 1024)
    base_v0v1_fk    = os.urandom(16)
    base_v0v1_dek   = os.urandom(16)
    base_v0v1_nonce = os.urandom(16)
    base_v2_fk      = os.urandom(16)  # rotation: alice was evicted
    base_v2_dek     = os.urandom(16)
    base_v2_nonce   = os.urandom(16)

    people = {n: X25519PrivateKey.generate()
              for n in ("alice", "bob", "charlie", "dave")}

    def make(members):
        bao = Bao()
        bao.grant("world", "reader", "friends#member")
        for n in members:
            bao.grant("friends", "member", n)
        expanded = bao.enumerate_recipients("world")
        return [(people[n], people[n].public_key()) for n in expanded]

    return world_content, [
        ("world_v0_initial",
         make(["alice", "bob", "charlie"]),
         base_v0v1_fk, base_v0v1_dek, base_v0v1_nonce),
        ("world_v1_dave_joined_group",
         make(["alice", "bob", "charlie", "dave"]),
         base_v0v1_fk, base_v0v1_dek, base_v0v1_nonce),
        ("world_v2_alice_left_group",
         make(["bob", "charlie", "dave"]),
         base_v2_fk, base_v2_dek, base_v2_nonce),
    ]


def main():
    OUT.mkdir(exist_ok=True)
    generic = [
        ("single_recipient_small",  b"the quick brown fox jumps over the lazy dog", 1),
        ("three_recipients_small",  b"multi-recipient wrap set", 3),
        ("empty_payload",           b"", 1),
        ("exactly_one_chunk",       b"a" * (64 * 1024), 1),
        ("just_over_one_chunk",     b"b" * (64 * 1024 + 1), 1),
        ("two_chunks",              b"c" * (128 * 1024), 1),
        ("multi_chunks_medium",     os.urandom(300 * 1024), 1),
        ("high_entropy_one_chunk",  os.urandom(32 * 1024), 1),
        ("repeated_content",        b"deadbeef" * 8192, 2),
        ("unicode_name",            "hello".encode() * 100, 1),
    ]
    # Social-VR scenarios: single-owner private avatar, shared world with a
    # small collaborator set, avatar shared to a friends list, ephemeral
    # instance asset, cross-instance world, published-public file (recipient
    # whose private key is openly published), and a post-revoke shared
    # world documenting what a wrap deletion looks like.
    scenarios = [
        ("private_avatar",             os.urandom(200 * 1024),  1),
        ("shared_world_small",         os.urandom(1024 * 1024), 5),
        ("shared_world_medium",        os.urandom(2 * 1024 * 1024), 12),
        ("friends_list_avatar",        os.urandom(200 * 1024), 10),
        ("ephemeral_instance_asset",   os.urandom(10 * 1024),   1),
        ("cross_instance_world",       os.urandom(1024 * 1024), 20),
        ("published_public",           b"openly readable payload", 1),
        ("post_revoke_shared_world",   os.urandom(1024 * 1024), 4),
    ]
    # Real VRM 1.0 avatar (SK_VRM1_Constraint_Twist_Sample, MIT-ish per
    # the repo's LICENSE.md) as a realistic payload for the friends-list
    # scenario. Skipped if the file isn't in the workspace yet.
    vrm_candidates = [
        REPO.parents[2] / "6-datasource" / "sk-vrm1-constraint-twist-sample"
            / "Constraint_Twist_Sample" / "Art" / "VRM1"
            / "VRM1_Constraint_Twist_Sample_01.vrm",
        pathlib.Path("/tmp/vrm-sample/Constraint_Twist_Sample/Art/VRM1/"
                     "VRM1_Constraint_Twist_Sample_01.vrm"),
    ]
    real_vrm = []
    vrm_path = next((p for p in vrm_candidates if p.exists()), None)
    if vrm_path:
        print(f"  found VRM at {vrm_path}")
        vrm_bytes = vrm_path.read_bytes()
        real_vrm.append(("vrm_avatar_friends_list", vrm_bytes, 10))
        # Data-buffer blob: VRM + one significant texture concatenated,
        # symbolising an avatar bundle a social-VR platform ships as
        # one unit. Uses the largest texture in the sample repo.
        tex = vrm_path.parents[1] / "Blend" / "textures" / "Thumbnail.png"
        if tex.exists():
            bundle = vrm_bytes + tex.read_bytes()
            real_vrm.append(("vrm_and_texture_bundle", bundle, 5))
            print(f"  found texture at {tex}")
    total = generic + scenarios + real_vrm
    for name, pt, nr in total:
        blob = vector(name, pt, nr)
        (OUT / name).write_bytes(blob)
        print(f"  wrote {name} ({len(pt)} B plaintext, {nr} recipient(s) -> {len(blob)} B vector)")

    # Exploded VRM: one vector per top-level stage directory. root is
    # a small USDA; the per-dir bundles concatenate the sub-stages
    # inside so every level of the tree flows through sqlar-cas.
    exploded_dir = OUT / "exploded" / "vrm"
    if exploded_dir.exists():
        exploded_vectors = [("vrm_exploded_root",
                             (exploded_dir / "root.usda").read_bytes(), 5)]
        for sub in ("scenes", "meshes", "materials", "textures",
                    "images", "nodes"):
            d = exploded_dir / sub
            if not d.exists():
                continue
            parts = []
            for f in sorted(d.iterdir()):
                parts.append(f"--- {f.name} ({f.stat().st_size} B) ---\n".encode())
                parts.append(f.read_bytes())
                parts.append(b"\n")
            exploded_vectors.append((f"vrm_exploded_{sub}", b"".join(parts), 5))
        for name, pt, nr in exploded_vectors:
            blob = vector(name, pt, nr)
            (OUT / name).write_bytes(blob)
            print(f"  wrote {name} ({len(pt)} B plaintext, {nr} recipient(s) -> {len(blob)} B vector)")
    else:
        exploded_vectors = []

    # Join-the-world: chunk dedup shares base across v0/v1 (readers
    # grow) but v2 rotates because alice left (reader-set shrink).
    jw_content, jw_vectors = gen_joined_world()
    for name, recipients, fk, dek, nonce in jw_vectors:
        blob = vector(name, jw_content, len(recipients),
                      recipients=recipients, file_key=fk,
                      dek_id=dek, payload_nonce=nonce)
        (OUT / name).write_bytes(blob)
        print(f"  wrote {name} ({len(jw_content)} B plaintext, {len(recipients)} recipient(s) -> {len(blob)} B vector)")

    print(f"generated {len(total) + len(jw_vectors) + len(exploded_vectors)} vectors in {OUT}")


if __name__ == "__main__":
    main()
