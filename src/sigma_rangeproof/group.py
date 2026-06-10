"""Prime-order group + Pedersen parameters for the range proof.

We work in the prime-order-``q`` subgroup of quadratic residues of a safe prime
``p = 2q + 1`` (RFC 3526 MODP groups are safe primes). Commitments live mod
``p``; exponents are reduced mod ``q``. Two generators ``g`` and ``h`` are fixed
such that ``log_g(h)`` is unknown (``h`` is derived by a nothing-up-my-sleeve
hash), which is what makes Pedersen commitments computationally binding.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

# ── RFC 3526 MODP Group 14 (2048-bit safe prime). Widely published constant. ──
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin primality test (probabilistic; safety net for the constant)."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


@dataclass(frozen=True)
class Params:
    """Group parameters: prime ``p``, subgroup order ``q``, generators ``g``, ``h``."""

    p: int
    q: int
    g: int
    h: int
    name: str = "rfc3526-modp14"

    @property
    def elem_bytes(self) -> int:
        return (self.p.bit_length() + 7) // 8

    def validate(self, *, check_primality: bool = False) -> None:
        """Assert the parameters describe a safe-prime QR subgroup.

        The structural checks (``q = (p-1)/2``, generators in the order-``q``
        subgroup) are cheap (a couple of modexps) and always run. The expensive
        Miller-Rabin primality test of ``p`` and ``q`` is gated behind
        ``check_primality`` — it's a one-time sanity check on the hard-coded
        constant, exercised in the test suite, not something to pay on import.
        """
        if self.q != (self.p - 1) // 2:
            raise ValueError("q must equal (p-1)/2 (safe-prime structure)")
        for label, e in (("g", self.g), ("h", self.h)):
            if not (1 < e < self.p):
                raise ValueError(f"{label} out of range")
            if pow(e, self.q, self.p) != 1:
                raise ValueError(f"{label} is not in the order-q subgroup")
        if check_primality:
            if not _is_probable_prime(self.p):
                raise ValueError("p is not prime")
            if not _is_probable_prime(self.q):
                raise ValueError("q is not prime (p must be a safe prime)")


def _hash_to_subgroup(p: int, label: bytes) -> int:
    """Derive a QR-subgroup element with unknown dlog (nothing-up-my-sleeve).

    Squaring maps an arbitrary residue into the order-``q`` subgroup; the base is
    a hash, so its discrete log relative to ``g`` is unknown.
    """
    counter = 0
    while True:
        digest = hashlib.sha512(label + counter.to_bytes(4, "big")).digest()
        candidate = int.from_bytes(digest, "big") % p
        elem = pow(candidate, 2, p)  # land in the QR subgroup
        if elem > 1:
            return elem
        counter += 1


def _build_default() -> Params:
    p = int(_P_HEX, 16)
    q = (p - 1) // 2
    g = 4  # = 2^2, a quadratic residue -> generator of the prime-order subgroup
    h = _hash_to_subgroup(p, b"sigma-rangeproof:h:v1")
    return Params(p=p, q=q, g=g, h=h)


# The default parameters, validated once at import.
DEFAULT_PARAMS = _build_default()
DEFAULT_PARAMS.validate()


def rand_scalar(params: Params = DEFAULT_PARAMS) -> int:
    """A uniform blinding/nonce scalar in ``[0, q)``."""
    return secrets.randbelow(params.q)


def in_subgroup(x: int, params: Params = DEFAULT_PARAMS) -> bool:
    """True iff ``x`` is a member of the order-``q`` subgroup ``G``.

    Untrusted group elements must be checked before use: an element outside
    ``G`` (e.g. a non-residue carrying the order-2 component) can otherwise slip
    through the verification algebra. Membership is ``x^q ≡ 1 (mod p)`` with
    ``x`` a non-zero residue.
    """
    return 0 < x < params.p and pow(x, params.q, params.p) == 1


def is_canonical_scalar(x: int, params: Params = DEFAULT_PARAMS) -> bool:
    """True iff ``x`` is a canonically reduced scalar in ``[0, q)``.

    Rejecting non-canonical scalars (e.g. ``z + q``, which verifies identically
    because ``h`` has order ``q``) makes proofs unique — important for any caller
    that hashes or deduplicates them.
    """
    return 0 <= x < params.q
