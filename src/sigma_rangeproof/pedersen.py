"""Pedersen commitments over the prime-order subgroup.

``Com(v, r) = g^v · h^r mod p`` — perfectly hiding, computationally binding.
"""

from __future__ import annotations

from .group import DEFAULT_PARAMS, Params, rand_scalar


def commit(value: int, blinding: int | None = None, *, params: Params = DEFAULT_PARAMS
           ) -> tuple[int, int]:
    """Commit to ``value``. Returns ``(commitment, blinding)``.

    ``blinding`` is generated uniformly if not supplied. The value is reduced
    mod ``q``; callers proving ranges must keep ``value`` a small non-negative
    integer (its true magnitude is what the range proof attests).
    """
    if blinding is None:
        blinding = rand_scalar(params)
    c = (pow(params.g, value % params.q, params.p)
         * pow(params.h, blinding % params.q, params.p)) % params.p
    return c, blinding


def open_commit(commitment: int, value: int, blinding: int, *,
                params: Params = DEFAULT_PARAMS) -> bool:
    """Check that ``commitment`` opens to ``(value, blinding)``."""
    expected, _ = commit(value, blinding, params=params)
    return commitment == expected
