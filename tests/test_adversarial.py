"""Adversarial tests: malleability, subgroup attacks, bit soundness, inputs.

These are the cases a verifier faces when the proof comes from someone trying to
cheat, as opposed to the happy-path tests in test_rangeproof.py.
"""

from copy import deepcopy

import pytest

from sigma_rangeproof import commit, prove_ge, verify_ge
from sigma_rangeproof.group import DEFAULT_PARAMS as P
from sigma_rangeproof.rangeproof import _prove_bit, _verify_bit
from sigma_rangeproof.transcript import Transcript


@pytest.fixture
def proof740():
    c, r = commit(740)
    return c, r, prove_ge(740, r, 700, bits=8)


# ─── Malleability: non-canonical scalars must be rejected ───────────────────

def test_response_plus_q_is_rejected(proof740):
    c, _, proof = proof740
    m = deepcopy(proof)
    m.bit_proofs[0]["z0"] += P.q          # h^(z+q) == h^z, but not canonical
    assert verify_ge(c, 700, m) is False


def test_challenge_shifted_by_q_is_rejected(proof740):
    c, _, proof = proof740
    m = deepcopy(proof)
    m.bit_proofs[1]["e0"] += P.q
    m.bit_proofs[1]["e1"] -= P.q          # sum mod q unchanged
    assert verify_ge(c, 700, m) is False


def test_negative_scalar_rejected(proof740):
    c, _, proof = proof740
    m = deepcopy(proof)
    m.bit_proofs[0]["z1"] -= P.q
    assert verify_ge(c, 700, m) is False


# ─── Subgroup membership: out-of-group elements must be rejected ────────────

def test_non_subgroup_commitment_rejected(proof740):
    c, _, proof = proof740
    c_bad = (c * (P.p - 1)) % P.p          # multiply by the order-2 element
    assert P.q and pow(c_bad, P.q, P.p) != 1
    assert verify_ge(c_bad, 700, proof) is False


def test_non_subgroup_bit_commitment_rejected(proof740):
    c, _, proof = proof740
    m = deepcopy(proof)
    m.commitments[0] = (m.commitments[0] * (P.p - 1)) % P.p
    assert verify_ge(c, 700, m) is False


def test_non_subgroup_a_value_rejected(proof740):
    c, _, proof = proof740
    m = deepcopy(proof)
    m.bit_proofs[0]["a0"] = (m.bit_proofs[0]["a0"] * (P.p - 1)) % P.p
    assert verify_ge(c, 700, m) is False


# ─── Bit soundness: a commitment to a non-bit cannot pass the bit proof ─────

def test_commitment_to_two_is_not_a_valid_bit():
    # A prover that does not know log_h(g) cannot make an honest OR-proof for a
    # commitment to 2. We try anyway (claiming bit=1) and verification must fail.
    from sigma_rangeproof.group import rand_scalar

    r = rand_scalar()
    c_two, _ = commit(2, r)              # g^2 h^r, not a bit commitment

    t = Transcript(P)
    t.append_int(b"Ci", c_two)
    bad_bit_proof = _prove_bit(t, c_two, 1, r, P)   # forge attempt

    t2 = Transcript(P)
    t2.append_int(b"Ci", c_two)
    assert _verify_bit(t2, c_two, bad_bit_proof, P) is False


# ─── A genuinely false statement cannot be proved ──────────────────────────

def test_cannot_prove_value_below_threshold():
    _, r = commit(500)
    with pytest.raises(ValueError):
        prove_ge(500, r, 700, bits=10)


def test_negative_inputs_rejected():
    _, r = commit(500)
    with pytest.raises(ValueError):
        prove_ge(500, r, -100, bits=64)
    with pytest.raises(ValueError):
        prove_ge(-1, r, 0, bits=64)


# ─── The fixes do not break honest proofs ──────────────────────────────────

def test_honest_proof_still_verifies(proof740):
    c, _, proof = proof740
    assert verify_ge(c, 700, proof) is True
