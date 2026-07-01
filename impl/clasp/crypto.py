"""
CLASP crypto core.

Two swappable layers behind clean interfaces:

  Group   : a prime-order group where DDH is assumed hard. The reference
            implementation is a subgroup of Z_p^* (fast, pure Python). The
            paper and production use a prime-order elliptic curve; the DDH
            structure the protocol relies on is identical, so the DOPRF and
            commitments are faithful. [DEVIATION: mod-p, not EC.]

  ThresholdAHE : a 2-of-2 threshold additively-homomorphic encryption scheme.
            The reference backend is threshold Paillier. The paper and the
            measured timings use the transparent-setup threshold class-group
            scheme (BICYCL). BICYCLBackend is the adapter you run on your Mac.
            [DEVIATION: reference keygen uses a trusted dealer; CL is
            transparent. This affects Setup realism, not aggregation
            correctness or timing shape.]

Nothing about cost is hidden: every deviation from the paper's instantiation
is marked with [DEVIATION].
"""
from __future__ import annotations
import secrets
from dataclasses import dataclass
import sympy


# --------------------------------------------------------------------------
# Prime-order group (reference: subgroup of Z_p^*)
# --------------------------------------------------------------------------

@dataclass
class Group:
    """Prime-order subgroup of Z_p^*: order q divides p-1, generator g."""
    p: int
    q: int
    g: int

    def rand_exp(self) -> int:
        return 1 + secrets.randbelow(self.q - 1)

    def exp(self, base: int, e: int) -> int:
        return pow(base, e % self.q, self.p)

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p

    def inv(self, a: int) -> int:
        return pow(a, -1, self.p)

    def hash_to_group(self, data: bytes) -> int:
        """Hash bytes to a group element of order q (random oracle H)."""
        import hashlib
        counter = 0
        while True:
            h = hashlib.sha256(data + counter.to_bytes(4, "big")).digest()
            x = int.from_bytes(h, "big") % self.p
            # map into the order-q subgroup by raising to the cofactor
            cof = (self.p - 1) // self.q
            elt = pow(x, cof, self.p)
            if elt != 1:
                return elt
            counter += 1


def gen_group(bits: int = 512) -> Group:
    """Generate p = 2q+1 (safe prime) so the subgroup has prime order q.
    512 bits is a fast reference size; use 2048+ for real DDH security.
    [DEVIATION: reference security level for speed; production uses EC-256.]"""
    while True:
        q = sympy.randprime(2 ** (bits - 1), 2 ** bits)
        p = 2 * q + 1
        if sympy.isprime(p):
            break
    # find a generator of the order-q subgroup
    while True:
        h = 2 + secrets.randbelow(p - 3)
        g = pow(h, 2, p)  # square -> lands in the order-q subgroup
        if g != 1:
            return Group(p=p, q=q, g=g)


# --------------------------------------------------------------------------
# Threshold additively-homomorphic encryption: interface
# --------------------------------------------------------------------------

class ThresholdAHE:
    """Interface. enc/add/scalar_mul/refresh are public; decryption is 2-of-2."""
    def enc(self, m: int) -> object: raise NotImplementedError
    def add(self, c1, c2): raise NotImplementedError
    def scalar_mul(self, a: int, c): raise NotImplementedError
    def refresh(self, c): raise NotImplementedError
    def part_dec(self, share_id: int, c) -> object: raise NotImplementedError
    def fin_dec(self, c, partials) -> int: raise NotImplementedError
    @property
    def plaintext_modulus(self) -> int: raise NotImplementedError


# --------------------------------------------------------------------------
# Reference backend: threshold Paillier (2-of-2 additive share of lambda)
# --------------------------------------------------------------------------

class PaillierTAHE(ThresholdAHE):
    def __init__(self, key_bits: int = 1024):
        # [DEVIATION: trusted dealer keygen; CL setup is transparent.]
        p = sympy.randprime(2 ** (key_bits // 2 - 1), 2 ** (key_bits // 2))
        q = sympy.randprime(2 ** (key_bits // 2 - 1), 2 ** (key_bits // 2))
        while q == p:
            q = sympy.randprime(2 ** (key_bits // 2 - 1), 2 ** (key_bits // 2))
        self.N = p * q
        self.N2 = self.N * self.N
        self.lam = sympy.lcm(p - 1, q - 1)          # Carmichael lambda
        self.mu = pow(int(self.lam), -1, self.N)    # since g = N+1
        # 2-of-2 additive threshold: split lambda into two integer shares
        self.lam1 = secrets.randbelow(int(self.lam))
        self.lam2 = int(self.lam) - self.lam1

    @property
    def plaintext_modulus(self) -> int:
        return self.N

    def enc(self, m: int):
        m = m % self.N
        while True:
            r = 1 + secrets.randbelow(self.N - 1)
            if sympy.gcd(r, self.N) == 1:
                break
        # g = N+1  =>  g^m = 1 + mN (mod N^2)
        c = ((1 + m * self.N) * pow(r, self.N, self.N2)) % self.N2
        return c

    def add(self, c1, c2):
        return (c1 * c2) % self.N2

    def scalar_mul(self, a: int, c):
        return pow(c, a % self.N, self.N2)

    def refresh(self, c):
        # multiply by a fresh encryption of 0
        return self.add(c, self.enc(0))

    def part_dec(self, share_id: int, c):
        lam_i = self.lam1 if share_id == 1 else self.lam2
        return pow(c, lam_i, self.N2)

    def fin_dec(self, c, partials):
        u = (partials[0] * partials[1]) % self.N2   # c^lambda
        L = (u - 1) // self.N
        return (L * self.mu) % self.N


# --------------------------------------------------------------------------
# BICYCL backend adapter (run on your Mac; not runnable in this sandbox)
# --------------------------------------------------------------------------

class BICYCLBackend(ThresholdAHE):
    """Adapter to the transparent-setup threshold class-group scheme via
    BICYCL. Not runnable here (no BICYCL, no network). On your M4, this wraps
    the CL-HSMqk operations whose per-op cost you already measured
    (enc 4.57 ms, add 8.85 us, dec 10.61 ms at 128-bit). Implement by binding
    BICYCL through pybind11 or by shelling out to a small C++ helper."""
    def __init__(self, *a, **k):
        raise NotImplementedError(
            "BICYCLBackend runs on your Mac against the compiled BICYCL. "
            "Use PaillierTAHE for the in-sandbox correctness and timing run.")
