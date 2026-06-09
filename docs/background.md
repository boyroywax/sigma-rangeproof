# The math you need

Everything here runs on three ideas: a group where multiplying is easy but
dividing (in the logarithm sense) is hard, the hardness itself, and a way to
lock a number inside a group element. Take them in order.

## A finite cyclic group

Fix a large prime \(p\). The nonzero remainders mod \(p\), written
\(\mathbb{Z}_p^*\), form a group under multiplication mod \(p\). It has \(p-1\)
elements. We do not want the whole thing; we want a piece of it with prime size,
because prime-size groups are clean to reason about and free of small subgroups
that leak information.

The library uses a *safe prime*: a prime \(p\) such that \(q = (p-1)/2\) is also
prime. In a safe prime group the quadratic residues, the elements that are
squares of something, form a subgroup \(G\) of size exactly \(q\). Since \(q\) is
prime, \(G\) has no nontrivial subgroups, and every element other than the
identity generates the whole of \(G\).

Pick a generator \(g\) of \(G\). Then \(G = \{g^0, g^1, \dots, g^{q-1}\}\) and the
exponents behave like the integers mod \(q\): \(g^a \cdot g^b = g^{a+b \bmod q}\)
and \((g^a)^b = g^{ab \bmod q}\). So group elements are numbers mod \(p\), but the
*exponents* live mod \(q\). Keeping those two moduli straight is most of what it
takes to read the code without tripping.

## The discrete logarithm problem

Given \(g\) and \(y = g^x\) in \(G\), finding \(x\) is the discrete logarithm
problem. Computing \(y\) from \(x\) is fast, a few hundred multiplications by
repeated squaring. Going back, recovering \(x\) from \(y\), is believed to take
time exponential in the size of \(p\) for a well-chosen group. At 2048 bits the
best known attacks put this around the 112-bit security mark, meaning the work to
break it is comparable to trying \(2^{112}\) possibilities.

Every security claim in this library reduces to that one assumption. Nothing here
is information-theoretically unbreakable against the binding side; it is
*computationally* sound, resting on the belief that nobody can take discrete
logs in this group.

## Two generators with no known relationship

The commitment needs a second generator \(h\), also in \(G\), with one extra
property: nobody knows an \(x\) such that \(h = g^x\). If someone did know that
relationship, they could open a commitment two different ways, which is exactly
what we are about to forbid.

You cannot just pick \(h\) at random and hope, because whoever picked it might
remember how. The library derives \(h\) by hashing a fixed string and squaring
the result into \(G\). Hashing gives an element nobody chose deliberately;
squaring lands it in the quadratic-residue subgroup. This is the
"nothing-up-my-sleeve" move, and it is why the construction needs no trusted
setup ceremony. The generator is reproducible by anyone and beholden to no one.

## Pedersen commitments

Now the lock. To commit to a value \(v\), draw a random blinding factor \(r\) from
\(\{0, \dots, q-1\}\) and compute

\[
C = g^{v} \, h^{r} \bmod p .
\]

That single group element \(C\) is the commitment. It has two properties that
pull in opposite directions, and getting both is the whole point.

**Perfectly hiding.** Because \(r\) is uniform and \(h\) generates \(G\), the term
\(h^r\) is a uniform element of \(G\), and multiplying by it smears \(g^v\)
uniformly across the group. So \(C\) is uniform no matter what \(v\) is. Two
different values produce identically distributed commitments. An attacker with
unlimited time learns nothing about \(v\) from \(C\); the information is simply
not there.

**Computationally binding.** Suppose you could open \(C\) two ways, as
\((v, r)\) and \((v', r')\) with \(v \neq v'\). Then \(g^v h^r = g^{v'} h^{r'}\),
so \(g^{v - v'} = h^{r' - r}\), which means

\[
h = g^{(v - v') (r' - r)^{-1} \bmod q}.
\]

You have just produced the discrete log of \(h\) base \(g\), the relationship we
said nobody knows. So opening a commitment two ways is as hard as the discrete
logarithm problem. In practice it cannot be done, and that is what makes a
commitment a commitment: once you publish \(C\), you are stuck with the value
inside it.

Notice the asymmetry. Hiding holds against any adversary, even one with infinite
compute. Binding holds only against a bounded one. Pedersen made that choice on
purpose; the opposite balance is possible with a different construction, but for
proving statements about a hidden value, perfect hiding is the side you want
firm.

## The one property that makes proofs possible

Pedersen commitments are *homomorphic*. Multiply two of them and you commit to
the sum:

\[
C_1 \cdot C_2 = g^{v_1} h^{r_1} \cdot g^{v_2} h^{r_2}
             = g^{v_1 + v_2} \, h^{r_1 + r_2} .
\]

Raise one to a power \(k\) and you scale the value:

\[
C^{k} = g^{kv} \, h^{kr} .
\]

This is the lever the range proof pulls on. The verifier never opens anything,
but it can take the public commitments and combine them, and the algebra carries
through to the hidden values underneath. When the [range proof](range-proof.md)
multiplies bit commitments together and checks the result, it is using exactly
these two identities to tie the bits back to the number without ever seeing it.
