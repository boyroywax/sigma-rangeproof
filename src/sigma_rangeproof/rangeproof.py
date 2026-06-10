"""Non-interactive zero-knowledge range proof via bit decomposition.

Proves, in zero knowledge, that a Pedersen commitment ``C = g^v · h^r`` hides a
value ``v`` with ``v ≥ threshold`` — without revealing ``v`` or ``r``.

How it works:

* The verifier can compute ``C' = C · g^(−threshold) = g^(v−threshold) · h^r``
  on its own. Let ``w = v − threshold``; proving ``w ∈ [0, 2^bits)`` proves
  ``v ≥ threshold`` (and ``v < threshold + 2^bits``).
* The prover bit-decomposes ``w = Σ b_i·2^i`` and commits to each bit
  ``C_i = g^(b_i)·h^(r_i)``, choosing the ``r_i`` so that ``Π C_i^(2^i) = C'``.
* For each bit it attaches a Fiat-Shamir OR-proof that ``C_i`` opens to ``0`` or
  ``1`` (a Chaum-Pedersen / CDS disjunction of two discrete-log statements over
  base ``h``).

The verifier checks the product identity and every bit OR-proof. Soundness rests
on the discrete-log assumption + Fiat-Shamir (random-oracle model); there is no
trusted setup.
"""

from __future__ import annotations

from dataclasses import dataclass

from .group import (
    DEFAULT_PARAMS,
    MAX_BITS,
    Params,
    in_subgroup,
    is_canonical_scalar,
    rand_scalar,
)
from .pedersen import commit
from .transcript import Transcript

__all__ = ["RangeProof", "prove_ge", "verify_ge"]


# ─── Per-bit OR proof (CDS disjunction over base h) ──────────────────────────


def _prove_bit(t: Transcript, c_i: int, bit: int, r_i: int, p: Params) -> dict:
    """Prove ``c_i`` commits to 0 or 1 (knows ``r_i`` s.t. it's ``h^r`` or ``g·h^r``)."""
    y0 = c_i
    y1 = (c_i * pow(p.g, -1, p.p)) % p.p  # c_i / g
    ys = (y0, y1)

    real, fake = (0, 1) if bit == 0 else (1, 0)

    # Simulate the fake branch: pick (e_fake, z_fake), back out its commitment.
    e_fake = rand_scalar(p)
    z_fake = rand_scalar(p)
    a_fake = (pow(p.h, z_fake, p.p) * pow(ys[fake], -e_fake % p.q, p.p)) % p.p

    # Honest commitment for the real branch.
    k = rand_scalar(p)
    a_real = pow(p.h, k, p.p)

    a = [0, 0]
    a[real], a[fake] = a_real, a_fake

    # Fiat-Shamir challenge binds both commitments.
    t.append_int(b"a0", a[0]).append_int(b"a1", a[1])
    e = t.challenge(b"bit")

    e_real = (e - e_fake) % p.q
    z_real = (k + e_real * r_i) % p.q

    e_arr = [0, 0]
    z_arr = [0, 0]
    e_arr[real], e_arr[fake] = e_real, e_fake
    z_arr[real], z_arr[fake] = z_real, z_fake

    return {"a0": a[0], "a1": a[1], "e0": e_arr[0], "e1": e_arr[1],
            "z0": z_arr[0], "z1": z_arr[1]}


def _verify_bit(t: Transcript, c_i: int, bp: dict, p: Params) -> bool:
    # Reject non-canonical scalars (z+q, e±q, ...) so a proof can't be mauled
    # into an equivalent-but-different one that still verifies.
    if not all(is_canonical_scalar(bp[k], p) for k in ("e0", "e1", "z0", "z1")):
        return False
    if not (in_subgroup(bp["a0"], p) and in_subgroup(bp["a1"], p)):
        return False

    y0 = c_i
    y1 = (c_i * pow(p.g, -1, p.p)) % p.p

    t.append_int(b"a0", bp["a0"]).append_int(b"a1", bp["a1"])
    e = t.challenge(b"bit")

    if (bp["e0"] + bp["e1"]) % p.q != e:
        return False
    # h^z_b == a_b · Y_b^{e_b}  for both branches
    lhs0 = pow(p.h, bp["z0"], p.p)
    rhs0 = (bp["a0"] * pow(y0, bp["e0"], p.p)) % p.p
    lhs1 = pow(p.h, bp["z1"], p.p)
    rhs1 = (bp["a1"] * pow(y1, bp["e1"], p.p)) % p.p
    return lhs0 == rhs0 and lhs1 == rhs1


# ─── Range proof ─────────────────────────────────────────────────────────────


@dataclass
class RangeProof:
    bits: int
    commitments: list[int]   # per-bit commitments C_i
    bit_proofs: list[dict]   # per-bit OR proofs

    def to_dict(self) -> dict:
        return {
            "bits": self.bits,
            "commitments": [hex(c) for c in self.commitments],
            "bit_proofs": [
                {k: hex(v) for k, v in bp.items()} for bp in self.bit_proofs
            ],
        }

    @classmethod
    def from_dict(cls, d: dict, *, params: Params = DEFAULT_PARAMS) -> RangeProof:
        """Parse a serialized proof, with strict bounds on every field.

        The bounds are intentionally cheap (length checks on the hex strings
        and a cap on ``bits``) so an untrusted proof cannot push the verifier
        into expensive modular arithmetic before the structural sanity checks
        have run. Cryptographic checks (subgroup, canonical scalar) still
        happen later in :func:`verify_ge`.
        """
        if not isinstance(d, dict):
            raise TypeError("proof must be a dict")
        try:
            bits = int(d["bits"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("missing or malformed 'bits'") from exc
        if not (1 <= bits <= MAX_BITS):
            raise ValueError(f"bits must be in [1, {MAX_BITS}]")

        commitments = d.get("commitments")
        bit_proofs = d.get("bit_proofs")
        if not isinstance(commitments, list) or len(commitments) != bits:
            raise ValueError("commitments must be a list of length bits")
        if not isinstance(bit_proofs, list) or len(bit_proofs) != bits:
            raise ValueError("bit_proofs must be a list of length bits")

        # `hex(x)` always emits a lowercase "0x" prefix, so the maximum length
        # of a serialized field is `2 + 2 * width_in_bytes`. Anything wider is
        # rejected before `int(s, 16)` runs — that's the DoS guard.
        max_elem_chars = 2 + 2 * params.elem_bytes
        max_scalar_chars = 2 + 2 * params.scalar_bytes

        def _parse_elem(s: object) -> int:
            if not isinstance(s, str) or len(s) > max_elem_chars:
                raise ValueError("group element encoding too wide")
            return int(s, 16)

        def _parse_scalar(s: object) -> int:
            if not isinstance(s, str) or len(s) > max_scalar_chars:
                raise ValueError("scalar encoding too wide")
            return int(s, 16)

        parsed_commitments = [_parse_elem(c) for c in commitments]
        parsed_bit_proofs: list[dict] = []
        required_keys = ("a0", "a1", "e0", "e1", "z0", "z1")
        for bp in bit_proofs:
            if not isinstance(bp, dict):
                raise ValueError("bit_proof entry must be a dict")
            missing = [k for k in required_keys if k not in bp]
            if missing:
                raise ValueError(f"bit_proof missing keys: {missing}")
            parsed_bit_proofs.append({
                "a0": _parse_elem(bp["a0"]),
                "a1": _parse_elem(bp["a1"]),
                "e0": _parse_scalar(bp["e0"]),
                "e1": _parse_scalar(bp["e1"]),
                "z0": _parse_scalar(bp["z0"]),
                "z1": _parse_scalar(bp["z1"]),
            })

        return cls(bits=bits, commitments=parsed_commitments, bit_proofs=parsed_bit_proofs)


def _seed(t: Transcript, commitment: int, threshold: int, bits: int,
          commitments: list[int]) -> None:
    t.append_int(b"C", commitment)
    t.append_int(b"threshold", threshold)
    t.append_int(b"bits", bits)
    for c_i in commitments:
        t.append_int(b"Ci", c_i)


def prove_ge(value: int, blinding: int, threshold: int, *, bits: int = 32,
             params: Params = DEFAULT_PARAMS) -> RangeProof:
    """Prove the commitment to ``(value, blinding)`` satisfies ``value ≥ threshold``.

    Raises ``ValueError`` if ``value - threshold`` is not in ``[0, 2^bits)`` — the
    prover simply cannot forge a proof outside the range.
    """
    if bits < 1:
        raise ValueError("bits must be >= 1")
    if bits > MAX_BITS:
        raise ValueError(f"bits must be <= {MAX_BITS}")
    if value < 0 or threshold < 0:
        raise ValueError("value and threshold must be non-negative")
    # Integer-domain invariants. With the default 2048-bit group ``q`` is huge
    # and these checks are formalities, but they prevent silent integer/modular
    # confusion under custom small-group parameters.
    if value >= params.q or threshold >= params.q:
        raise ValueError("value and threshold must be < q")
    if (1 << bits) >= params.q:
        raise ValueError("2^bits must be < q")
    w = value - threshold
    if w < 0 or w >= (1 << bits):
        raise ValueError("value - threshold out of [0, 2^bits); cannot prove")

    p = params
    commitment, _ = commit(value, blinding, params=p)

    # Bit blindings r_i chosen so that Σ 2^i · r_i ≡ blinding (mod q); then
    # Π C_i^(2^i) = g^w · h^blinding = C' exactly.
    r = [rand_scalar(p) for _ in range(bits)]
    partial = sum((1 << i) * r[i] for i in range(bits - 1)) % p.q
    inv_top = pow(pow(2, bits - 1, p.q), -1, p.q)
    r[bits - 1] = ((blinding - partial) * inv_top) % p.q

    bit_vals = [(w >> i) & 1 for i in range(bits)]
    commitments = [commit(bit_vals[i], r[i], params=p)[0] for i in range(bits)]

    t = Transcript(p)
    _seed(t, commitment, threshold, bits, commitments)
    bit_proofs = [_prove_bit(t, commitments[i], bit_vals[i], r[i], p) for i in range(bits)]

    return RangeProof(bits=bits, commitments=commitments, bit_proofs=bit_proofs)


def verify_ge(commitment: int, threshold: int, proof: RangeProof, *,
              params: Params = DEFAULT_PARAMS) -> bool:
    """Verify a :func:`prove_ge` proof against the public ``commitment``."""
    p = params
    bits = proof.bits
    # Bound work before any modular exponentiation: a hostile proof must not
    # be able to inflate verifier cost by claiming an absurd ``bits`` value.
    if not (1 <= bits <= MAX_BITS):
        return False
    if len(proof.commitments) != bits or len(proof.bit_proofs) != bits:
        return False
    if not (0 <= threshold < p.q):
        return False

    # Untrusted group elements must be inside the prime-order subgroup, or the
    # verification algebra can be satisfied with out-of-group elements.
    if not in_subgroup(commitment, p):
        return False
    if not all(in_subgroup(c_i, p) for c_i in proof.commitments):
        return False

    # C' = C · g^(-threshold)
    c_prime = (commitment * pow(pow(p.g, threshold, p.p), -1, p.p)) % p.p

    # Π C_i^(2^i) must reconstruct C' (binds the bits to the committed value).
    acc = 1
    for i in range(bits):
        acc = (acc * pow(proof.commitments[i], 1 << i, p.p)) % p.p
    if acc != c_prime:
        return False

    t = Transcript(p)
    _seed(t, commitment, threshold, bits, proof.commitments)
    return all(
        _verify_bit(t, proof.commitments[i], proof.bit_proofs[i], p)
        for i in range(bits)
    )
