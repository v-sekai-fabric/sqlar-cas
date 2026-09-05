#!/usr/bin/env python3
"""Verify one sqlar-cas test vector under testdata/.

Reads the text header + SQLite body, unwraps the file_key with each
recipient's private key, decrypts the envelope, reassembles the
chunks, and asserts sha256(plaintext) matches the header's payload
field.
"""

import argparse
import hashlib
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from sqlar_cas_py import extract_from_sqlite  # noqa: E402

REPO = HERE.parent
TESTDATA = REPO / "testdata"
CHUNK_STORE = TESTDATA / "chunks"


def parse_vector(path):
    data = path.read_bytes()
    sep = data.find(b"\n\n")
    if sep < 0:
        raise ValueError(f"{path.name}: no header/body separator")
    headers = {}
    for line in data[:sep].decode().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers, data[sep + 2 :]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("vector", nargs="?", default="single_recipient_small")
    args = ap.parse_args()

    p = TESTDATA / args.vector
    if not p.exists():
        sys.exit(f"vector not found: {p}")

    headers, sqlite_blob = parse_vector(p)
    print(f"vector: {args.vector}")
    print(f"  expected payload sha256: {headers['payload_sha256']}")
    print(f"  chunks: {headers['num_chunks']}  recipients: {headers['num_recipients']}")

    n = int(headers["num_recipients"])
    passes = 0
    for i in range(n):
        priv = bytes.fromhex(headers[f"recipient_priv_{i}"])
        plaintext = extract_from_sqlite(
            sqlite_blob, headers["name"], priv, chunk_store=CHUNK_STORE,
        )
        computed = hashlib.sha256(plaintext).hexdigest()
        if computed != headers["payload_sha256"]:
            sys.exit(f"recipient {i}: payload mismatch — got {computed}")
        if len(plaintext) != int(headers["payload_size"]):
            sys.exit(f"recipient {i}: size mismatch")
        passes += 1
    print(f"  ok  {passes}/{n} recipients recovered plaintext")
    print("all checks passed")


if __name__ == "__main__":
    main()
