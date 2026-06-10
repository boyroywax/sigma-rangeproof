"""Property-based fuzzing with Hypothesis.

These tests assert invariants over thousands of randomized inputs rather than a
handful of hand-picked ones. The point is to catch the failure case nobody
thought to write down: a value/threshold/bits combination that breaks the
round trip, or a proof mutation that slips past verification.

Two profiles are registered:

* ``dev`` (default) runs a small number of examples, because each proof is many
  modular exponentiations and an interpreter under emulation is slow.
* ``ci`` runs a large number, suitable for a native machine.

Select with the environment variable, e.g.::

    HYPOTHESIS_PROFILE=ci pytest tests/test_fuzz.py
"""

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sigma_rangeproof import commit, prove_ge, verify_ge
from sigma_rangeproof.group import DEFAULT_PARAMS as P
from sigma_rangeproof.rangeproof import RangeProof

_HEALTH = [HealthCheck.too_slow, HealthCheck.data_too_large]
# dev: a quick smoke set for slow/local interpreters.
# ci:  a solid sweep for native pipeline runners (each op is ~ms there).
# soak: an exhaustive run for scheduled/nightly jobs.
settings.register_profile("dev", max_examples=10, deadline=None, suppress_health_check=_HEALTH)
settings.register_profile("ci", max_examples=500, deadline=None, suppress_health_check=_HEALTH)
settings.register_profile("soak", max_examples=5000, deadline=None, suppress_health_check=_HEALTH)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))


@st.composite
def in_range_case(draw):
    """A (value, threshold, bits) triple with value - threshold in [0, 2^bits)."""
    bits = draw(st.integers(min_value=1, max_value=12))
    threshold = draw(st.integers(min_value=0, max_value=1000))
    w = draw(st.integers(min_value=0, max_value=(1 << bits) - 1))
    return threshold + w, threshold, bits


# ─── Correctness invariants ──────────────────────────────────────────────────

@given(in_range_case())
def test_roundtrip_always_verifies(case):
    value, threshold, bits = case
    c, r = commit(value)
    proof = prove_ge(value, r, threshold, bits=bits)
    assert verify_ge(c, threshold, proof) is True
    # serialization must preserve validity
    assert verify_ge(c, threshold, RangeProof.from_dict(proof.to_dict())) is True


@given(threshold=st.integers(1, 5000), gap=st.integers(1, 5000), bits=st.integers(1, 16))
def test_below_threshold_always_raises(threshold, gap, bits):
    value = threshold - gap
    if value < 0:
        return  # negative value is a separate check
    _, r = commit(value)
    with pytest.raises(ValueError):
        prove_ge(value, r, threshold, bits=bits)


@given(value=st.integers(max_value=-1), threshold=st.integers(0, 100), bits=st.integers(1, 16))
def test_negative_value_always_raises(value, threshold, bits):
    _, r = commit(0)
    with pytest.raises(ValueError):
        prove_ge(value, r, threshold, bits=bits)


# ─── Soundness invariants: any deviation must be rejected ────────────────────

@given(in_range_case(), st.integers(min_value=1, max_value=2**32))
def test_any_other_threshold_is_rejected(case, bump):
    value, threshold, bits = case
    c, r = commit(value)
    proof = prove_ge(value, r, threshold, bits=bits)
    other = threshold + (bump % 4096) + 1   # guaranteed != threshold
    assert verify_ge(c, other, proof) is False


@given(in_range_case(), st.integers(0, 1 << 20),
       st.sampled_from(["e0", "e1", "z0", "z1"]), st.integers(1, 2**32))
def test_scalar_tamper_is_rejected(case, which, field, delta):
    value, threshold, bits = case
    c, r = commit(value)
    proof = prove_ge(value, r, threshold, bits=bits)
    idx = which % len(proof.bit_proofs)
    d = delta % (P.q - 1) + 1            # in [1, q-1] -> a genuinely different scalar
    proof.bit_proofs[idx][field] = (proof.bit_proofs[idx][field] + d) % P.q
    assert verify_ge(c, threshold, proof) is False


@given(in_range_case(), st.integers(0, 1 << 20), st.integers(1, 2**32))
def test_commitment_tamper_is_rejected(case, which, kexp):
    value, threshold, bits = case
    c, r = commit(value)
    proof = prove_ge(value, r, threshold, bits=bits)
    idx = which % len(proof.commitments)
    k = kexp % (P.q - 1) + 1             # multiply a bit commitment by g^k, k != 0
    proof.commitments[idx] = (proof.commitments[idx] * pow(P.g, k, P.p)) % P.p
    assert verify_ge(c, threshold, proof) is False


@given(in_range_case(), st.integers(1, 2**32))
def test_wrong_commitment_is_rejected(case, kexp):
    value, threshold, bits = case
    c, r = commit(value)
    proof = prove_ge(value, r, threshold, bits=bits)
    k = kexp % (P.q - 1) + 1
    other = (c * pow(P.g, k, P.p)) % P.p   # a different (still in-subgroup) commitment
    assert verify_ge(other, threshold, proof) is False
