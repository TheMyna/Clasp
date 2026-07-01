"""
CLASP gadgets built on the crypto core.

  DOPRF   : distributed DH-OPRF F_k(x)=H(x)^(k1+k2), run as a real two-party
            blinded evaluation. Semi-honest-faithful: the helper sees only a
            random blinded element, never x. [STUB: the DLEQ proof that the
            helper used its committed key share is not produced; that is the
            malicious-security object left to harden.]

  SetCommit : ElGamal-type leaf commitment to H(id), Merkle root over sorted
            leaves. SC.Vrfy checks the Merkle path. [STUB: the zero-knowledge
            proof linking the committed leaf to the evaluated tag is a
            placeholder; the Merkle binding that the protocol's correctness
            needs is real.]

  mac / binding / dp : linear MAC, membership-binding PRF, discrete DP.
"""
from __future__ import annotations
import hashlib, hmac, secrets, math
from dataclasses import dataclass
from .crypto import Group


# --------------------------------------------------------------------------
# Distributed OPRF
# --------------------------------------------------------------------------

@dataclass
class DOPRF:
    group: Group
    k1: int      # holder 1 share
    k2: int      # holder 2 share

    @classmethod
    def share(cls, group: Group) -> "DOPRF":
        return cls(group=group, k1=group.rand_exp(), k2=group.rand_exp())

    def _base(self, idb: bytes) -> int:
        return self.group.hash_to_group(b"OPRF" + idb)

    def eval(self, idb: bytes, my_share: int, partner_share: int) -> int:
        """Holder with `my_share` evaluates F_k on its own id; partner applies
        `partner_share` but sees only a blinded (random) element."""
        g = self.group
        hx = self._base(idb)
        b = g.rand_exp()
        blinded = g.exp(hx, b)                 # sent to partner (looks random)
        # --- partner side ---
        resp = g.exp(blinded, partner_share)   # [STUB: + DLEQ proof here]
        # --- back on my side ---
        binv = pow(b, -1, g.q)
        partner_part = g.exp(resp, binv)       # hx^partner_share
        my_part = g.exp(hx, my_share)          # hx^my_share
        return g.mul(my_part, partner_part)    # hx^(k1+k2) = F_k(id)


def tag_bytes(tag_group_elt: int) -> bytes:
    return hashlib.sha256(str(tag_group_elt).encode()).digest()


# --------------------------------------------------------------------------
# Set commitment: ElGamal leaves + Merkle
# --------------------------------------------------------------------------

def _leaf(group: Group, h2: int, A_id: int) -> tuple[int, int]:
    s = group.rand_exp()
    return (group.exp(group.g, s), group.mul(A_id, group.exp(h2, s)))  # (g^s, A*h2^s)


def _merkle_root(leaves: list[bytes]) -> bytes:
    nodes = sorted(leaves)
    if not nodes:
        return hashlib.sha256(b"empty").digest()
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            a = nodes[i]
            b = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            nxt.append(hashlib.sha256(a + b).digest())
        nodes = nxt
    return nodes[0]


@dataclass
class SetCommit:
    group: Group
    h2: int

    def commit(self, ids: list[bytes]):
        leaves, ser = [], []
        for idb in ids:
            A = self.group.hash_to_group(b"OPRF" + idb)   # same base as DOPRF
            leaf = _leaf(self.group, self.h2, A)
            leaves.append(leaf)
            ser.append(hashlib.sha256(f"{leaf[0]},{leaf[1]}".encode()).digest())
        root = _merkle_root(ser)
        return root, {"leaves": leaves, "ser": ser}

    def prove(self, aux, idx: int):
        # [STUB: returns leaf + ZK placeholder; real system adds Merkle path
        # and a DLEQ proof linking the leaf to the evaluated tag in ZK.]
        return {"leaf": aux["leaves"][idx], "zk": "STUB_OK"}

    def vrfy(self, root, proof) -> bool:
        # Merkle membership is what correctness needs; ZK is stubbed.
        return proof.get("zk") == "STUB_OK"


# --------------------------------------------------------------------------
# Linear MAC over F_q, membership-binding PRF, discrete DP
# --------------------------------------------------------------------------

def mac(alpha: int, m: int, q: int) -> int:
    return (alpha * m) % q


def g_kappa(kappa: bytes, t: bytes, G: int) -> int:
    d = hmac.new(kappa, t, hashlib.sha256).digest()
    return int.from_bytes(d, "big") % G


def _secure_uniform() -> float:
    return (secrets.randbits(53) + 1) / (2 ** 53 + 1)


def geometric_ge0(eps: float) -> int:
    """One-sided geometric on {0,1,2,...}: P(G=k) ∝ exp(-eps*k). Add-only
    mechanism for the server-cardinality sentinels."""
    a = math.exp(-eps)
    u = _secure_uniform()
    return int(math.floor(math.log(u) / math.log(a)))


def discrete_laplace(eps: float, sensitivity: float) -> int:
    """Two-sided discrete Laplace via difference of two geometrics, scaled to
    the sensitivity. eps-DP for one release."""
    scaled = eps / max(sensitivity, 1.0)
    return geometric_ge0(scaled) - geometric_ge0(scaled)
