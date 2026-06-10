"""Validate the published known-answer test vectors against this implementation.

These are the same vectors (tests/vectors/kat.json) an independent
implementation checks itself against. Here they double as a regression lock: if
a change alters the group, the encoding, or verification behavior, one of these
fails.
"""

import json
import os

import pytest

from sigma_rangeproof import RangeProof, commit, verify_ge
from sigma_rangeproof.group import DEFAULT_PARAMS as P
from sigma_rangeproof.group import _hash_to_subgroup
from sigma_rangeproof.transcript import Transcript

with open(os.path.join(os.path.dirname(__file__), "vectors", "kat.json")) as _f:
    KAT = json.load(_f)


def test_group_parameters_match():
    g = KAT["group"]
    assert int(g["p"], 16) == P.p
    assert int(g["q"], 16) == P.q
    assert int(g["g"], 16) == P.g
    assert int(g["h"], 16) == P.h
    assert g["elem_bytes"] == P.elem_bytes


def test_h_derivation_is_reproducible():
    g = KAT["group"]
    assert _hash_to_subgroup(P.p, g["h_label"].encode()) == int(g["h"], 16)


@pytest.mark.parametrize("vec", KAT["pedersen"], ids=lambda v: f"v{v['value']}")
def test_pedersen_commitments(vec):
    c, _ = commit(vec["value"], int(vec["blinding"], 16))
    assert c == int(vec["commitment"], 16)


def test_transcript_challenge():
    tv = KAT["transcript_challenge"]
    t = Transcript(P)
    t.append_int(tv["append_int"]["label"].encode(), tv["append_int"]["value"])
    e = t.challenge(tv["challenge_label"].encode())
    assert e == int(tv["challenge"], 16)


@pytest.mark.parametrize("vec", KAT["verify"], ids=lambda v: v["name"][:40])
def test_verify_vectors(vec):
    result = verify_ge(
        int(vec["commitment"], 16),
        vec["threshold"],
        RangeProof.from_dict(vec["proof"]),
    )
    assert result is vec["expected"]
