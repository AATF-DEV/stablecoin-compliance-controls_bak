#!/usr/bin/env python3
"""Build depth-160 sparse Merkle trees over random restricted addresses and emit
non-membership proofs for two fixed (unrestricted) addresses.

Convention must match src/SMTToken.sol:
  empty subtree = 0, H(0,0) = 0, H(l,r) = keccak256(l||r)
  restricted leaf = keccak256(key(20 bytes) || 0x01)
  at height h the branch bit is bit h of the key (bit 0 at the leaf level)

Usage: python3 scripts/gen_smt.py 1 10 100 1000 10000 100000
Writes data/smt_<N>.json
"""
import json
import random
import sys
import time
from pathlib import Path

from Crypto.Hash import keccak

DEPTH = 160
ZERO = b"\x00" * 32
SENDER = 0x5B38DA6A701C568545DCFCB03FCB875F56BEDDC4
RECIPIENT = 0xAB8483F64D9C6D1ECF9B849AE677DD3315835CB2


def k256(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


def H(l: bytes, r: bytes) -> bytes:
    if l == ZERO and r == ZERO:
        return ZERO
    return k256(l + r)


def build(keys):
    levels = [{k: k256(k.to_bytes(20, "big") + b"\x01") for k in keys}]
    for h in range(DEPTH):
        cur = levels[-1]
        nxt = {}
        for p in cur:
            q = p >> 1
            if q in nxt:
                continue
            nxt[q] = H(cur.get(2 * q, ZERO), cur.get(2 * q + 1, ZERO))
        levels.append(nxt)
    assert len(levels[DEPTH]) == 1
    return levels, levels[DEPTH][0]


def proof(levels, key):
    bitmap, sibs = 0, []
    for h in range(DEPTH):
        s = levels[h].get((key >> h) ^ 1, ZERO)
        if s != ZERO:
            bitmap |= 1 << h
            sibs.append("0x" + s.hex())
    return bitmap, sibs


def verify(key, leaf, bitmap, sibs, root):
    node, j = leaf, 0
    for h in range(DEPTH):
        s = ZERO
        if (bitmap >> h) & 1:
            s = bytes.fromhex(sibs[j][2:]); j += 1
        if node == ZERO and s == ZERO:
            continue
        node = H(s, node) if (key >> h) & 1 else H(node, s)
    return node == root


def main(ns):
    out = Path(__file__).resolve().parent.parent / "data"
    out.mkdir(exist_ok=True)
    for n in ns:
        t0 = time.time()
        rng = random.Random(1000 + n)
        keys = set()
        while len(keys) < n:
            k = rng.getrandbits(160)
            if k not in (SENDER, RECIPIENT):
                keys.add(k)
        levels, root = build(keys)
        doc = {"n": n, "root": "0x" + root.hex()}
        for name, key in (("sender", SENDER), ("recipient", RECIPIENT)):
            bm, sibs = proof(levels, key)
            assert verify(key, ZERO, bm, sibs, root), "non-membership proof failed"
            doc[name] = {"bitmap": str(bm), "siblings": sibs, "nonzero": len(sibs)}
        # a member proof (restricted key) to test that the contract rejects it
        mk = min(keys)
        bm, sibs = proof(levels, mk)
        leaf = levels[0][mk]
        assert verify(mk, leaf, bm, sibs, root)
        assert not verify(mk, ZERO, bm, sibs, root)
        doc["member"] = {"key": "0x%040x" % mk, "bitmap": str(bm), "siblings": sibs}
        (out / f"smt_{n}.json").write_text(json.dumps(doc))
        print(f"N={n:>7}  sender sibs={doc['sender']['nonzero']:>3}  "
              f"recipient sibs={doc['recipient']['nonzero']:>3}  {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main([int(x) for x in sys.argv[1:]] or [1, 10, 100, 1000, 10000])
