"""sigma-rangeproof — a small, dependency-free zero-knowledge range proof.

Prove ``value ≥ threshold`` over a Pedersen commitment without revealing the
value, using a Sigma-protocol bit-decomposition proof (Fiat-Shamir
non-interactive). No trusted setup, no native dependencies.

    from sigma_rangeproof import commit, prove_ge, verify_ge

    c, r = commit(740)                 # publish c; keep r secret
    proof = prove_ge(740, r, 700)      # "the committed value is >= 700"
    assert verify_ge(c, 700, proof)    # verifier learns only the boolean
"""

from __future__ import annotations

from .group import (
    DEFAULT_PARAMS,
    MAX_BITS,
    Params,
    in_subgroup,
    is_canonical_scalar,
    rand_scalar,
)
from .pedersen import commit, open_commit
from .rangeproof import RangeProof, prove_ge, verify_ge

__version__ = "0.1.2"

__all__ = [
    "commit",
    "open_commit",
    "prove_ge",
    "verify_ge",
    "RangeProof",
    "Params",
    "DEFAULT_PARAMS",
    "MAX_BITS",
    "rand_scalar",
    "in_subgroup",
    "is_canonical_scalar",
    "__version__",
]
