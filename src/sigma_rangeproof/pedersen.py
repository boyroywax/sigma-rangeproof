"""Pedersen commitments over the prime-order subgroup.

``Com(v, r) = g^v · h^r mod p`` — perfectly hiding, computationally binding.
"""

from __future__ import annotations

from .group import DEFAULT_PARAMS, Params, rand_scalar


def commit(value: int, blinding: int | None = None, *, params: Params = DEFAULT_PARAMS
           ) -> tuple[int, int]:
    """Commit to ``value``. Returns ``(commitment, blinding)``.

    ``blinding`` is generated uniformly if not supplied. Both ``value`` and
    ``blinding`` must lie in ``[0, q)``: silently reducing them mod ``q`` would
    paper over caller bugs (e.g. confusing the integer threshold window with
    the modular exponent) and, with custom small-group parameters, would mean
    the commitment hides a different integer than the caller asked for.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("value must be an int")
    if not (0 <= value < params.q):
        raise ValueError("value must be in [0, q)")
    if blinding is None:
        blinding = rand_scalar(params)
    else:
        if not isinstance(blinding, int) or isinstance(blinding, bool):
            raise TypeError("blinding must be an int")
        if not (0 <= blinding < params.q):
            raise ValueError("blinding must be in [0, q)")
    c = (pow(params.g, value, params.p) * pow(params.h, blinding, params.p)) % params.p
    return c, blinding


def open_commit(commitment: int, value: int, blinding: int, *,
                params: Params = DEFAULT_PARAMS) -> bool:
    """Check that ``commitment`` opens to ``(value, blinding)``."""
    # Out-of-range openings cannot match any well-formed commitment; treat
    # them as a clean ``False`` rather than letting the underlying
    # ``commit()`` raise (callers checking openings should not need to
    # pre-validate adversarial input).
    if not (0 <= value < params.q and 0 <= blinding < params.q):
        return False
    expected, _ = commit(value, blinding, params=params)
    return commitment == expected
