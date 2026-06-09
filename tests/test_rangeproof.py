"""Correctness + soundness tests for the range proof."""

import pytest

from sigma_rangeproof import DEFAULT_PARAMS, commit, open_commit, prove_ge, verify_ge
from sigma_rangeproof.rangeproof import RangeProof


def test_default_params_are_a_safe_prime_subgroup():
    # One-time, expensive safety net on the hard-coded constant (Miller-Rabin).
    DEFAULT_PARAMS.validate(check_primality=True)


def test_commit_open_roundtrip():
    c, r = commit(740)
    assert open_commit(c, 740, r)
    assert not open_commit(c, 741, r)


def test_prove_and_verify_above_threshold():
    c, r = commit(740)
    proof = prove_ge(740, r, 700, bits=16)
    assert verify_ge(c, 700, proof) is True


def test_prove_and_verify_at_threshold():
    c, r = commit(500)
    proof = prove_ge(500, r, 500, bits=16)  # w = 0
    assert verify_ge(c, 500, proof) is True


def test_prove_below_threshold_is_impossible():
    _, r = commit(680)
    with pytest.raises(ValueError):
        prove_ge(680, r, 700, bits=16)  # 680 - 700 < 0


def test_proof_does_not_verify_for_higher_threshold():
    # A proof for "≥700" must NOT validate as a proof for "≥720": the verifier
    # derives C' from its own threshold, so the bit product won't reconstruct.
    c, r = commit(740)
    proof = prove_ge(740, r, 700, bits=16)
    assert verify_ge(c, 720, proof) is False


def test_tampered_bit_commitment_fails():
    c, r = commit(740)
    proof = prove_ge(740, r, 700, bits=16)
    proof.commitments[0] = (proof.commitments[0] * 2) % 0xFFFFFFFF
    assert verify_ge(c, 700, proof) is False


def test_tampered_response_fails():
    c, r = commit(740)
    proof = prove_ge(740, r, 700, bits=16)
    proof.bit_proofs[3]["z0"] += 1
    assert verify_ge(c, 700, proof) is False


def test_wrong_commitment_fails():
    c, r = commit(740)
    proof = prove_ge(740, r, 700, bits=16)
    other, _ = commit(740)  # different blinding -> different commitment
    assert verify_ge(other, 700, proof) is False


def test_serialization_roundtrip():
    c, r = commit(900)
    proof = prove_ge(900, r, 256, bits=16)
    restored = RangeProof.from_dict(proof.to_dict())
    assert verify_ge(c, 256, restored) is True


def test_zero_knowledge_two_proofs_differ():
    # Fresh randomness each time -> proofs differ but both verify (hiding).
    c, r = commit(740)
    p1 = prove_ge(740, r, 700, bits=16)
    p2 = prove_ge(740, r, 700, bits=16)
    assert p1.to_dict() != p2.to_dict()
    assert verify_ge(c, 700, p1) and verify_ge(c, 700, p2)


@pytest.mark.parametrize("value,threshold", [(1, 0), (1000, 0), (1000, 999), (1023, 0)])
def test_range_edges(value, threshold):
    c, r = commit(value)
    proof = prove_ge(value, r, threshold, bits=10)
    assert verify_ge(c, threshold, proof) is True
