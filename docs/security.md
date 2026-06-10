# Security and parameters

Read this page before you put anything real behind the library. The construction
is standard, but standard constructions still have edges, and a few of them are
easy to walk off.

## What it assumes

Two assumptions hold the whole thing up.

The first is the **discrete logarithm assumption** in the 2048-bit safe-prime
group. Binding of the commitment, special soundness of the Schnorr proofs, and
therefore soundness of the range proof all reduce to it. If discrete logs in this
group became easy, a cheater could open commitments two ways and prove false
statements. At 2048 bits the best known attacks sit around 112 bits of security,
which is comfortable for most uses and below what you would pick for protecting
something for decades.

The second is the **random-oracle model**, which is how Fiat-Shamir turns the
interactive protocols non-interactive. The challenge is a hash output, and the
soundness argument treats that hash as an ideal random function. This is a
heuristic rather than a theorem about SHA-256, but it is the same heuristic under
a great deal of deployed cryptography, and no practical attack is known against
careful instantiations.

Hiding is stronger than either of these. It is *perfect*: a commitment reveals
nothing about its value even to an adversary with unlimited time. That property
does not rest on any computational assumption, only on the blinding factor being
uniform, which brings us to the first way to hold it wrong.

## Ways to hold it wrong

**Reusing or leaking a blinding factor.** The blinding is what makes the
commitment hiding. If you publish it, or generate it from a weak source, or reuse
the same one across commitments to related values, you can undermine hiding.
Treat a blinding like a private key: store it next to the value, never beside the
commitment, and let the library generate it from `secrets`.

**Confusing the moduli.** Group elements are taken mod `p`; exponents are taken
mod `q`. The library handles this internally, but if you extend it, mixing the
two is the classic way to introduce a subtle and silent break.

**Picking `bits` too small.** The proof covers \([T, T + 2^{\text{bits}})\). If a
value can exceed that window, an honest prover simply cannot make a proof and
`prove_ge` raises. That is a correctness annoyance, not a security hole, but be
aware the upper bound is real and is part of what you are proving.

**Treating the upper bound as nothing.** A proof of \(v \ge T\) is also a proof of
\(v < T + 2^{\text{bits}}\). Usually that is harmless or even useful, but if your
threat model cares about the upper end, account for it.

**Assuming the verifier authenticates the prover.** A range proof says "the value
in this commitment clears the bar." It does not say who made the commitment or
that they are allowed to. Binding the proof to an identity, a session, or a
freshness nonce is the caller's job, layered on top. The transcript already
absorbs the group parameters and the statement, so a proof cannot be replayed
under a different group or threshold, but it can be replayed verbatim if you do
not tie it to context.

## Nonces, randomness, and side channels

**Nonces must be fresh and never reused.** Every Schnorr commitment uses a random
nonce \(k\), and the OR-proof simulator draws random \((e_\text{fake},
z_\text{fake})\). These come from Python's `secrets`, a cryptographically secure
source. The hazard to understand: reusing a nonce across two different challenges
is the textbook way to leak a witness — two responses \(z = k + e x\) and
\(z' = k + e' x\) with the same \(k\) give \(x = (z-z')(e-e')^{-1}\), exactly the
extractor from the [Sigma page](sigma-protocols.md). The library never reuses a
nonce, and because the challenge is derived by Fiat-Shamir from a transcript that
includes the commitment, the same statement re-proved draws fresh randomness and
a fresh challenge each time. If you port the construction, keep that property:
either a CSPRNG per proof, or a deterministic nonce bound to the secret and the
full transcript (RFC 6979 style). A predictable or repeated nonce is game over.

**It is not constant-time.** The heavy lifting is Python's built-in `pow`, which
is not constant-time, so running times depend on secret exponents (the value and
the blinding). For this library's intended use — proving a public-ish threshold
about a score — the timing channel is a minor concern, and Python offers no
real constant-time big-integer path anyway. But do not use it to guard a secret
where an attacker can measure prove-time precisely; that would want a
constant-time backend (typically a native curve library), which is a different
project.

**API invariants.** A `Transcript` is single-use and statement-specific: it is
constructed fresh inside each `prove_ge` / `verify_ge` call, seeded with that
exact statement, and not shared across proofs. Do not reuse a commitment under a
different statement, and do not feed one proof's transcript to another — the
binding that makes the proof non-malleable depends on the transcript covering the
whole statement and nothing else.

## What verification enforces on an untrusted proof

A proof arriving from a stranger is hostile until checked, and `verify_ge`
treats it that way. Three classes of malformed input are rejected outright,
before the algebra runs.

Every group element in the proof, the commitment and each bit commitment, is
checked for membership in the prime-order subgroup with \(x^{q} \equiv 1\). An
element outside the subgroup, for instance one carrying the order-2 component,
can otherwise satisfy parts of the verification equation and is a classic way to
sneak past a naive verifier. The per-bit commitments produced inside the proof
are checked the same way.

Every scalar in the proof, the two challenges and two responses per bit, must be
canonically reduced into \([0, q)\). Without this check a proof is malleable:
because \(h\) has order \(q\), adding \(q\) to a response or shifting \(q\)
between the two challenge halves yields a different-looking proof that still
verifies. That does not let anyone prove a false statement, but it breaks any
caller that treats a proof as unique, say by hashing it for replay protection or
deduplication. Rejecting non-canonical scalars makes the encoding unique.

The threshold and bit width are bound into the proof through the transcript and
the product identity, so a proof made for one threshold does not verify under
another, and the positions of the bits cannot be reordered. What verification
does *not* do is tie the proof to a sender, a session, or a moment in time; that
is context the caller layers on, as noted above.

## Why these parameters

The prime is RFC 3526 group 14, a 2048-bit safe prime that has been public and
scrutinized for many years. Using a well-known constant rather than a freshly
generated one is a feature here: there is no setup, nothing to trust about how it
was chosen, and you can cross-check the value against the RFC. The generator `g`
is a small square, and the second generator `h` is hash-derived, so the
relationship between them is unknown to everyone, which is exactly what binding
needs.

The honest reason it is a prime-field group and not an elliptic curve: this
library is pure Python, and Python's built-in `pow` does modular exponentiation in
fast C, whereas elliptic-curve point arithmetic written in Python would run in the
interpreter and end up slower. A curve at 256 bits would give more security per
operation, but only with a native library doing the point math, which would mean
a compiled dependency. The pure-Python constraint is what tips the choice to a
2048-bit field.

## What "tested" covers, and does not

The suite checks that honest proofs verify across the range, that an
out-of-range value cannot be proved, that a proof does not validate under a
different threshold or a different commitment, that tampering with a bit
commitment or a response is caught, that proofs serialise and deserialise
faithfully, and that the bundled prime really is a safe prime. It also confirms
two proofs of the same fact differ, which is the visible sign of the randomness
that hiding depends on.

What the suite does not give you is an audit. Nobody outside has tried to break
it. The construction is old and well understood, and the code is short enough to
review in a sitting, but those reduce risk rather than removing it. For anything
high-value, get another set of eyes on it first.
