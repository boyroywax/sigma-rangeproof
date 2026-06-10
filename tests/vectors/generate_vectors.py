"""Regenerate the known-answer test vectors (tests/vectors/kat.json).

Run from the repo root:  python tests/vectors/generate_vectors.py

Most vectors are deterministic (group parameters, h-derivation, Pedersen
commitments with fixed blindings, a fixed transcript challenge). Proofs are
randomized, so we freeze *one* valid proof plus several invalid mutations; a
conforming implementation re-verifies them and must match the `expected` flags.
Only the verifier is exercised by those, and verification is deterministic.
"""

from __future__ import annotations

import copy
import json
import os

from sigma_rangeproof import __version__, commit, prove_ge, verify_ge
from sigma_rangeproof.group import DEFAULT_PARAMS as P
from sigma_rangeproof.group import _hash_to_subgroup
from sigma_rangeproof.transcript import Transcript

H_LABEL = b"sigma-rangeproof:h:v1"

OUT = os.path.join(os.path.dirname(__file__), "kat.json")


def _pedersen_vectors() -> list[dict]:
    cases = [
        (0, 2),
        (1, 3),
        (73, 0xDEADBEEFCAFE),
        (100, 0x0123456789ABCDEF0123456789ABCDEF),
    ]
    out = []
    for value, blinding in cases:
        c, _ = commit(value, blinding)
        out.append({"value": value, "blinding": hex(blinding), "commitment": hex(c)})
    return out


def _challenge_vector() -> dict:
    t = Transcript(P)  # absorbs domain, p, g, h
    t.append_int(b"x", 12345)
    e = t.challenge(b"test")
    return {
        "description": (
            "Fresh Transcript(DEFAULT_PARAMS) (absorbs domain,p,g,h in that order),"
            " then append_int('x', 12345), then challenge('test')."
        ),
        "append_int": {"label": "x", "value": 12345},
        "challenge_label": "test",
        "challenge": hex(e),
    }


def _verify_vectors() -> list[dict]:
    value, blinding, threshold, bits = 740, 0xABCDEF0123456789, 700, 8
    c, _ = commit(value, blinding)
    proof = prove_ge(value, blinding, threshold, bits=bits)
    assert verify_ge(c, threshold, proof) is True
    pd = proof.to_dict()

    def mutate(fn) -> dict:
        d = copy.deepcopy(pd)
        fn(d)
        return d

    tampered = mutate(
        lambda d: d["bit_proofs"][0].__setitem__(
            "z0", hex(int(d["bit_proofs"][0]["z0"], 16) + 1)
        )
    )
    noncanon = mutate(
        lambda d: d["bit_proofs"][0].__setitem__(
            "z0", hex(int(d["bit_proofs"][0]["z0"], 16) + P.q)
        )
    )
    bad_ci = mutate(
        lambda d: d["commitments"].__setitem__(
            0, hex(int(d["commitments"][0], 16) * (P.p - 1) % P.p)
        )
    )
    return [
        {"name": "valid: committed 740 >= 700", "commitment": hex(c),
         "threshold": threshold, "expected": True, "proof": pd},
        {"name": "reject: same proof at a higher threshold (720)", "commitment": hex(c),
         "threshold": 720, "expected": False, "proof": pd},
        {"name": "reject: response z0 incremented by 1", "commitment": hex(c),
         "threshold": threshold, "expected": False, "proof": tampered},
        {"name": "reject: non-canonical z0 (+q)", "commitment": hex(c),
         "threshold": threshold, "expected": False, "proof": noncanon},
        {"name": "reject: out-of-subgroup commitment (C * (p-1))",
         "commitment": hex(c * (P.p - 1) % P.p), "threshold": threshold,
         "expected": False, "proof": pd},
        {"name": "reject: out-of-subgroup bit commitment C_0", "commitment": hex(c),
         "threshold": threshold, "expected": False, "proof": bad_ci},
    ]


def build() -> dict:
    assert _hash_to_subgroup(P.p, H_LABEL) == P.h, "h derivation mismatch"
    return {
        "package": "sigma-rangeproof",
        "version": __version__,
        "note": (
            "Known-answer test vectors. Group params, h-derivation, Pedersen "
            "commitments and the transcript challenge are deterministic. The "
            "verify vectors freeze one valid proof plus invalid mutations a "
            "conforming verifier MUST reject."
        ),
        "group": {
            "name": P.name,
            "p": hex(P.p),
            "q": hex(P.q),
            "g": hex(P.g),
            "h": hex(P.h),
            "h_label": H_LABEL.decode(),
            "elem_bytes": P.elem_bytes,
        },
        "pedersen": _pedersen_vectors(),
        "transcript_challenge": _challenge_vector(),
        "verify": _verify_vectors(),
    }


if __name__ == "__main__":
    with open(OUT, "w") as f:
        json.dump(build(), f, indent=2)
        f.write("\n")
    print(f"wrote {OUT}")
