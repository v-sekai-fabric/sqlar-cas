"""Shared sqlar-cas primitives for the driver + vector scripts.

Everything here matches the age v1.1.0 construction (c2sp.org/age@v1.1.0)
where age applies. Chunks deviate from age STREAM to preserve CAS dedup:
per-chunk ChaCha20-Poly1305 with a content-derived nonce, zstd first,
addressed by SHA-512/256 of the ct.
"""

import base64
import hashlib
import hmac
import os
import pathlib
import sqlite3
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
import zstandard as zstd


CHUNK_BYTES = 64 * 1024
VERSION_BYTE = 1


def sha512_256(data):
    return hashlib.sha512(data).digest()[:32]


def hkdf(ikm, salt, info, length):
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def payload_key(file_key):
    return hkdf(file_key, b"\x00" * 16, b"payload", 32)


def mac_key(file_key):
    return hkdf(file_key, b"", b"header", 32)


def x25519_wrap_key(eph_priv, recipient_pub_bytes, eph_pub_bytes):
    peer = X25519PublicKey.from_public_bytes(recipient_pub_bytes)
    shared = eph_priv.exchange(peer)
    return hkdf(
        shared, eph_pub_bytes + recipient_pub_bytes,
        b"age-encryption.org/v1/X25519", 32,
    )


def x25519_wrap(recipient_pub_bytes, file_key):
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    wk = x25519_wrap_key(eph_priv, recipient_pub_bytes, eph_pub_bytes)
    aead = ChaCha20Poly1305(wk)
    wrapped = aead.encrypt(b"\x00" * 12, file_key, None)
    return eph_pub_bytes, wrapped


def x25519_unwrap(recipient_priv_bytes, eph_pub_bytes, wrapped_key):
    priv = X25519PrivateKey.from_private_bytes(recipient_priv_bytes)
    peer = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared = priv.exchange(peer)
    recipient_pub_bytes = priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    wk = hkdf(
        shared, eph_pub_bytes + recipient_pub_bytes,
        b"age-encryption.org/v1/X25519", 32,
    )
    aead = ChaCha20Poly1305(wk)
    return aead.decrypt(b"\x00" * 12, wrapped_key, None)


def header_bytes(dek_id, payload_nonce, name):
    return bytes([VERSION_BYTE]) + dek_id + payload_nonce + name.encode("utf-8")


def build_caibx(chunks_meta):
    out = struct.pack("<I", len(chunks_meta))
    for ct_hash, pt_hash, size in chunks_meta:
        out += ct_hash + pt_hash + struct.pack("<Q", size)
    return out


def parse_caibx(caibx):
    n = struct.unpack("<I", caibx[:4])[0]
    out = []
    off = 4
    for _ in range(n):
        ct_hash = caibx[off : off + 32]
        pt_hash = caibx[off + 32 : off + 64]
        size = struct.unpack("<Q", caibx[off + 64 : off + 72])[0]
        out.append((ct_hash, pt_hash, size))
        off += 72
    return out


def ingest_plaintext(plaintext, name, recipients_pub, file_key=None,
                     dek_id=None, payload_nonce=None):
    file_key = file_key or os.urandom(16)
    dek_id = dek_id or os.urandom(16)
    payload_nonce = payload_nonce or os.urandom(16)

    pk = payload_key(file_key)
    aead = ChaCha20Poly1305(pk)
    zctx = zstd.ZstdCompressor()

    chunks = []
    for i in range(0, max(1, len(plaintext)), CHUNK_BYTES):
        raw = plaintext[i : i + CHUNK_BYTES]
        pt_hash = sha512_256(raw)
        nonce = pt_hash[:12]
        compressed = zctx.compress(raw)
        ct = aead.encrypt(nonce, compressed, None)
        ct_hash = sha512_256(ct)
        chunks.append((ct_hash, ct, pt_hash, len(raw)))

    caibx = build_caibx([(c[0], c[2], c[3]) for c in chunks])
    hb = header_bytes(dek_id, payload_nonce, name)
    envelope_ct = aead.encrypt(payload_nonce[:12], caibx, hb)
    hmac_key = mac_key(file_key)
    header_mac = hmac.new(hmac_key, hb, hashlib.sha256).digest()
    sqlar_data = bytes([VERSION_BYTE]) + dek_id + payload_nonce + envelope_ct + header_mac

    wraps = []
    for pub_bytes in recipients_pub:
        eph_pub, wrapped = x25519_wrap(pub_bytes, file_key)
        wraps.append((eph_pub, wrapped))

    return {
        "file_key": file_key,
        "dek_id": dek_id,
        "payload_nonce": payload_nonce,
        "sqlar_data": sqlar_data,
        "caibx": caibx,
        "chunks": chunks,
        "wraps": wraps,
    }


def build_sqlite(name, ingested):
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite") as tmp:
        path = tmp.name
    try:
        db = sqlite3.connect(path)
        db.executescript("""
            CREATE TABLE sqlar(
              name TEXT PRIMARY KEY, mode INT, mtime INT,
              sz INT, data BLOB, dek_id BLOB);
            CREATE TABLE sqlar_dek_wraps(
              dek_id BLOB, ephemeral_pub BLOB, wrapped_key BLOB,
              PRIMARY KEY(dek_id, ephemeral_pub));
            CREATE TABLE sqlar_chunks(hash BLOB PRIMARY KEY, ct BLOB);
        """)
        db.execute(
            "INSERT INTO sqlar(name, mode, mtime, sz, data, dek_id) VALUES (?,0,0,?,?,?)",
            (name, sum(c[3] for c in ingested["chunks"]),
             ingested["sqlar_data"], ingested["dek_id"]),
        )
        for eph_pub, wrapped in ingested["wraps"]:
            db.execute(
                "INSERT INTO sqlar_dek_wraps(dek_id, ephemeral_pub, wrapped_key) VALUES (?,?,?)",
                (ingested["dek_id"], eph_pub, wrapped),
            )
        for ct_hash, ct, _pt, _sz in ingested["chunks"]:
            db.execute(
                "INSERT OR IGNORE INTO sqlar_chunks(hash, ct) VALUES (?, ?)",
                (ct_hash, ct),
            )
        db.commit()
        db.close()
        return pathlib.Path(path).read_bytes()
    finally:
        os.unlink(path)


def extract_from_sqlite(sqlite_bytes, name, recipient_priv_bytes):
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite") as tmp:
        tmp.write(sqlite_bytes)
        path = tmp.name
    try:
        db = sqlite3.connect(path)
        _plaintext = _extract_from_db(db, name, recipient_priv_bytes)
        db.close()
        return _plaintext
    finally:
        os.unlink(path)


def _extract_from_db(db, name, recipient_priv_bytes):
    row = db.execute(
        "SELECT data, dek_id FROM sqlar WHERE name = ?", (name,)
    ).fetchone()
    if not row:
        raise KeyError(f"no sqlar row named {name!r}")
    sqlar_data, dek_id = row

    version = sqlar_data[0]
    if version != VERSION_BYTE:
        raise ValueError(f"unknown version {version}")
    dek_id_field = sqlar_data[1:17]
    payload_nonce = sqlar_data[17:33]
    envelope_ct = sqlar_data[33:-32]
    header_mac_field = sqlar_data[-32:]

    file_key = None
    for eph_pub, wrapped in db.execute(
        "SELECT ephemeral_pub, wrapped_key FROM sqlar_dek_wraps WHERE dek_id = ?",
        (dek_id_field,),
    ):
        try:
            file_key = x25519_unwrap(recipient_priv_bytes, eph_pub, wrapped)
            break
        except Exception:
            continue
    if file_key is None:
        raise PermissionError("no wrap unwraps for this recipient")

    hb = header_bytes(dek_id_field, payload_nonce, name)
    hmac_key = mac_key(file_key)
    expected_mac = hmac.new(hmac_key, hb, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, header_mac_field):
        raise ValueError("header MAC mismatch")

    pk = payload_key(file_key)
    aead = ChaCha20Poly1305(pk)
    caibx = aead.decrypt(payload_nonce[:12], envelope_ct, hb)
    entries = parse_caibx(caibx)

    zctx = zstd.ZstdDecompressor()
    out = bytearray()
    for ct_hash, pt_hash, _sz in entries:
        (ct,) = db.execute(
            "SELECT ct FROM sqlar_chunks WHERE hash = ?", (ct_hash,)
        ).fetchone()
        raw = zctx.decompress(aead.decrypt(pt_hash[:12], ct, None))
        if sha512_256(raw) != pt_hash:
            raise ValueError("plaintext hash mismatch on chunk")
        out.extend(raw)
    return bytes(out)


def priv_to_bytes(priv):
    return priv.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption(),
    )


def pub_to_bytes(pub):
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


class Bao:
    """Zanzibar-style ReBAC. Tuples are (object, relation, userset).
    A userset is either a plain subject or 'object#relation' — a
    computed userset that expand() resolves recursively (cycle-safe).

    The store as rebase: file_key + chunks are the base; the wrap set
    is a rebase of grants/revokes on top. A grant is a commit; a
    revoke is a revert. Recursive relations let a change to a group
    (a new member, or someone leaving) ripple to every object that
    grants readers to that group#member — the joined-the-world case.
    """

    def __init__(self):
        self._tuples = set()  # {(object, relation, userset)}
        self._audit = []

    def grant(self, obj, relation, userset):
        self._tuples.add((obj, relation, userset))
        self._audit.append(("grant", obj, relation, userset))

    def revoke(self, obj, relation, userset):
        self._tuples.discard((obj, relation, userset))
        self._audit.append(("revoke", obj, relation, userset))

    def expand(self, obj, relation, seen=None):
        seen = seen or set()
        if (obj, relation) in seen:
            return set()
        seen = seen | {(obj, relation)}
        out = set()
        for (o, r, u) in self._tuples:
            if o != obj or r != relation:
                continue
            if "#" in u:
                sub_obj, sub_rel = u.split("#", 1)
                out |= self.expand(sub_obj, sub_rel, seen)
            else:
                out.add(u)
        return out

    def authorize_write_wrap(self, subject, obj):
        return subject in self.expand(obj, "reader")

    def enumerate_recipients(self, obj):
        return sorted(self.expand(obj, "reader"))

    def audit_log(self):
        return list(self._audit)

