#!/usr/bin/env python3
"""Drive a CCTV age v1.1.0 test vector end-to-end.

Pipeline:  openbao (modelled) -> age STREAM decrypt -> sqlar-cas ingest
        -> sqlite tables + desync chunk-store layout -> sqlar-cas extract
        -> verify sha256(plaintext) matches CCTV's `payload:` header.

Bao is modelled -- not stubbed -- for its ReBAC properties. Every wrap
insertion goes through Bao.authorize_write_wrap; every read enumerates
recipients through Bao.enumerate_recipients. The model records grants
in a set; a production replacement talks to a real Bao instance with
the same interface. Desync is stubbed to a Python impl of the
<outer>/<hash>.cacnk chunk-store layout because desync-c isn't in
this workspace yet.
"""

import argparse
import base64
import hashlib
import os
import pathlib
import sqlite3
import sys
import tempfile
import zlib

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import zstandard as zstd

HERE = pathlib.Path(__file__).resolve()
CCTV_ROOT = HERE.parents[3] / "6-datasource" / "cctv" / "age" / "testdata"


class Bao:
    """Models Bao's ReBAC. Grants are (subject, object, relation) tuples;
    a wrap insertion is authorized iff the grant is present. Enumeration
    tells the ingest path who to wrap for. Not a stub -- a real Bao
    replaces this class through the same interface."""

    def __init__(self):
        self._grants: set[tuple[str, str, str]] = set()
        self._wrap_writes: list[tuple[str, str]] = []

    def grant(self, subject: str, obj: str) -> None:
        self._grants.add((subject, obj, "reader"))

    def revoke(self, subject: str, obj: str) -> None:
        self._grants.discard((subject, obj, "reader"))

    def authorize_write_wrap(self, subject: str, obj: str) -> bool:
        ok = (subject, obj, "reader") in self._grants
        if ok:
            self._wrap_writes.append((subject, obj))
        return ok

    def enumerate_recipients(self, obj: str) -> list[str]:
        return [s for (s, o, _r) in self._grants if o == obj]

    def audit_log(self) -> list[tuple[str, str]]:
        return list(self._wrap_writes)


def parse_vector(path):
    text = path.read_bytes()
    sep = text.find(b"\n\n")
    if sep < 0:
        raise ValueError(f"{path.name}: no blank-line separator")
    headers_raw, body = text[:sep], text[sep + 2 :]
    headers = {}
    for line in headers_raw.decode().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers, body


def hkdf(ikm, salt, info, length):
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def sha512_256(data):
    return hashlib.sha512(data).digest()[:32]


def unarmor(wire):
    lines = wire.splitlines()
    body_lines = []
    inside = False
    for ln in lines:
        s = ln.strip()
        if s.startswith(b"-----BEGIN AGE"):
            inside = True
            continue
        if s.startswith(b"-----END AGE"):
            inside = False
            continue
        if inside and s:
            body_lines.append(s)
    return base64.b64decode(b"".join(body_lines))


def age_wire_split(wire):
    pos = 0
    while pos < len(wire):
        nl = wire.find(b"\n", pos)
        if nl < 0:
            raise ValueError("no header MAC line found")
        line = wire[pos:nl]
        if line.startswith(b"--- "):
            return wire[nl + 1 :]
        pos = nl + 1
    raise ValueError("no header MAC line found")


def age_stream_decrypt(file_key, payload):
    if len(payload) < 16:
        raise ValueError("STREAM payload shorter than 16-byte nonce prefix")
    nonce_prefix = payload[:16]
    body = payload[16:]
    payload_key = hkdf(file_key, nonce_prefix, b"payload", 32)
    aead = ChaCha20Poly1305(payload_key)
    CHUNK_CT = 64 * 1024 + 16
    out = bytearray()
    counter = 0
    pos = 0
    while pos < len(body):
        take = min(CHUNK_CT, len(body) - pos)
        chunk_ct = body[pos : pos + take]
        pos += take
        is_last = pos >= len(body)
        nonce = counter.to_bytes(11, "big") + (b"\x01" if is_last else b"\x00")
        out.extend(aead.decrypt(nonce, chunk_ct, None))
        counter += 1
    return bytes(out)


def sqlar_ingest(plaintext, name, db, bao: Bao, recipients: list[str]):
    file_key = os.urandom(16)
    dek_id = os.urandom(16)
    payload_key = hkdf(file_key, b"\x00" * 16, b"payload", 32)
    aead = ChaCha20Poly1305(payload_key)
    zctx = zstd.ZstdCompressor()
    CHUNK = 64 * 1024

    for r in recipients:
        if not bao.authorize_write_wrap(r, name):
            raise PermissionError(f"Bao refused wrap for {r!r} on {name!r}")

    chunks = []
    for i in range(0, max(1, len(plaintext)), CHUNK):
        raw = plaintext[i : i + CHUNK]
        pt_hash = sha512_256(raw)
        nonce = pt_hash[:12]
        compressed = zctx.compress(raw)
        ct = aead.encrypt(nonce, compressed, None)
        ct_hash = sha512_256(ct)
        chunks.append((ct_hash, ct, pt_hash, len(raw)))

    db.execute(
        "INSERT INTO sqlar(name, mode, mtime, sz, data, dek_id) VALUES (?,0,0,?,?,?)",
        (name, len(plaintext), b"", dek_id),
    )
    for r in recipients:
        db.execute(
            "INSERT INTO sqlar_dek_wraps(dek_id, principal, ephemeral_pub, wrapped_key) VALUES (?,?,?,?)",
            (dek_id, r, b"", b""),
        )
    for ct_hash, ct, _pt, _sz in chunks:
        db.execute(
            "INSERT OR IGNORE INTO sqlar_chunks(hash, ct) VALUES (?, ?)",
            (ct_hash, ct),
        )
    db.commit()
    return dek_id, file_key, chunks


def sqlar_extract(name, file_key, chunks, db, bao: Bao):
    granted = bao.enumerate_recipients(name)
    if not granted:
        raise PermissionError(f"Bao says no readers on {name!r}")
    payload_key = hkdf(file_key, b"\x00" * 16, b"payload", 32)
    aead = ChaCha20Poly1305(payload_key)
    zctx = zstd.ZstdDecompressor()
    out = bytearray()
    for ct_hash, _ct, pt_hash, _sz in chunks:
        row = db.execute(
            "SELECT ct FROM sqlar_chunks WHERE hash = ?", (ct_hash,)
        ).fetchone()
        if row is None:
            raise RuntimeError(f"chunk {ct_hash.hex()} missing")
        nonce = pt_hash[:12]
        raw = zctx.decompress(aead.decrypt(nonce, row[0], None))
        if sha512_256(raw) != pt_hash:
            raise RuntimeError("plaintext hash mismatch")
        out.extend(raw)
    return bytes(out)


def desync_path(chunk_hash):
    hx = chunk_hash.hex()
    return f"{hx[:4]}/{hx}.cacnk"


def emit_desync_store(chunks, root):
    for ct_hash, ct, _pt, _sz in chunks:
        p = pathlib.Path(root) / desync_path(ct_hash)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(ct)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vector", default="x25519")
    args = ap.parse_args()

    vector = CCTV_ROOT / args.vector
    if not vector.exists():
        sys.exit(f"vector not found: {vector}")
    headers, wire = parse_vector(vector)
    if headers.get("expect") != "success":
        sys.exit(f"skipping non-success vector ({headers.get('expect')})")

    if headers.get("compressed", "").lower() == "zlib":
        wire = zlib.decompress(wire)
    if headers.get("armored", "").lower() in ("yes", "true"):
        wire = unarmor(wire)

    print(f"vector: {args.vector}")
    print(f"  expected payload sha256: {headers['payload']}")

    file_key_hex = headers.get("file key")
    if not file_key_hex:
        sys.exit("driver needs the `file key:` header (shortcut around wrap)")
    file_key = bytes.fromhex(file_key_hex)

    stream_payload = age_wire_split(wire)
    plaintext = age_stream_decrypt(file_key, stream_payload)
    computed = hashlib.sha256(plaintext).hexdigest()
    print(f"  computed payload sha256: {computed}")
    if computed != headers["payload"]:
        sys.exit(f"payload mismatch: got {computed}, want {headers['payload']}")
    print("  ok  age STREAM decrypt matches CCTV expected hash")

    bao = Bao()
    bao.grant("alice", args.vector)
    bao.grant("bob", args.vector)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite") as tmp:
        db_path = tmp.name
    with tempfile.TemporaryDirectory() as chunk_root:
        db = sqlite3.connect(db_path)
        db.executescript(
            """
            CREATE TABLE sqlar(
              name TEXT PRIMARY KEY, mode INT, mtime INT,
              sz INT, data BLOB, dek_id BLOB);
            CREATE TABLE sqlar_dek_wraps(
              dek_id BLOB, principal TEXT, ephemeral_pub BLOB, wrapped_key BLOB,
              PRIMARY KEY(dek_id, principal));
            CREATE TABLE sqlar_chunks(hash BLOB PRIMARY KEY, ct BLOB);
            """
        )
        recipients = bao.enumerate_recipients(args.vector)
        _dek_id, fk, chunks = sqlar_ingest(plaintext, args.vector, db, bao, recipients)
        print(f"  ok  Bao authorized {len(recipients)} wrap(s); {len(chunks)} chunk(s) into {db_path}")

        emit_desync_store(chunks, chunk_root)
        print(f"  ok  desync store written at {chunk_root}")

        recovered = sqlar_extract(args.vector, fk, chunks, db, bao)
        if recovered != plaintext:
            sys.exit("sqlar-cas roundtrip failed")
        print("  ok  sqlar-cas extract roundtrip bit-for-bit")

        bao.revoke("alice", args.vector)
        try:
            _ = sqlar_ingest(b"secondary", args.vector + ".v2", db, bao,
                             ["alice"])
            sys.exit("ReBAC bypass: revoked alice's wrap insert should be refused")
        except PermissionError:
            print("  ok  post-revoke, Bao refused wrap insert for revoked principal")

        for ct_hash, ct, _pt, _sz in chunks:
            p = pathlib.Path(chunk_root) / desync_path(ct_hash)
            if p.read_bytes() != ct:
                sys.exit(f"desync store mismatch at {p}")
        print("  ok  desync store roundtrip bit-for-bit")

        print(f"  audit: Bao logged {len(bao.audit_log())} wrap write(s)")

    os.unlink(db_path)
    print("all checks passed")


if __name__ == "__main__":
    main()
