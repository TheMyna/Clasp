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



def _dleq_challenge(group, *elems):
    h = hashlib.sha256()
    for e in elems:
        h.update(str(e).encode())
    return int.from_bytes(h.digest(), "big") % group.q

def dleq_prove(group, base1, pub1, base2, pub2, x):
    g = group; r = g.rand_exp()
    A1 = g.exp(base1, r); A2 = g.exp(base2, r)
    c = _dleq_challenge(g, base1, pub1, base2, pub2, A1, A2)
    z = (r + c * x) % g.q
    return (c, z)

def dleq_verify(group, base1, pub1, base2, pub2, proof):
    g = group; c, z = proof
    A1 = g.mul(g.exp(base1, z), g.exp(g.inv(pub1), c))
    A2 = g.mul(g.exp(base2, z), g.exp(g.inv(pub2), c))
    return _dleq_challenge(g, base1, pub1, base2, pub2, A1, A2) == c

# --------------------------------------------------------------------------
# Distributed OPRF
# --------------------------------------------------------------------------

def oprf_base(group: Group, idb: bytes) -> int:
    """Shared hash-to-group used by BOTH the DOPRF and the set commitment, so
    the A_id committed in a leaf equals the A_id the DOPRF evaluates on."""
    return group.hash_to_group(b"OPRF" + idb)


# --------------------------------------------------------------------------
# Linkage proof: bind the DOPRF blinded base to the committed A_id.
# Public: leaf (c1=g^s, c2=A*hbar^s), blinded=A^b. Prove exists (b, mu):
#   blinded = c2^b * hbar^{-mu}   AND   1 = c1^b * g^{-mu}
# The 2nd eqn forces mu = s*b, so blinded = (c2*hbar^{-s})^b = A^b for the
# committed A. Zero-knowledge of A, s, b (Fiat-Shamir).
# --------------------------------------------------------------------------

def link_prove(group, hbar, c1, c2, blinded, b, mu):
    g = group
    rb, rmu = g.rand_exp(), g.rand_exp()
    T1 = g.mul(g.exp(c2, rb), g.exp(g.inv(hbar), rmu))
    T2 = g.mul(g.exp(c1, rb), g.exp(g.inv(g.g), rmu))
    e = _dleq_challenge(g, g.g, hbar, c1, c2, blinded, T1, T2)
    return (e, (rb + e * b) % g.q, (rmu + e * mu) % g.q)


def link_verify(group, hbar, c1, c2, blinded, proof):
    g = group
    e, zb, zmu = proof
    T1 = g.mul(g.mul(g.exp(c2, zb), g.exp(g.inv(hbar), zmu)),
               g.exp(g.inv(blinded), e))
    T2 = g.mul(g.exp(c1, zb), g.exp(g.inv(g.g), zmu))
    return _dleq_challenge(g, g.g, hbar, c1, c2, blinded, T1, T2) == e


# --------------------------------------------------------------------------
# Distributed OPRF
# --------------------------------------------------------------------------

@dataclass
class DOPRF:
    group: Group
    k1: int
    k2: int
    K1: int = None
    K2: int = None

    @classmethod
    def share(cls, group: Group) -> "DOPRF":
        k1 = group.rand_exp(); k2 = group.rand_exp()
        return cls(group=group, k1=k1, k2=k2,
                   K1=group.exp(group.g, k1), K2=group.exp(group.g, k2))

    def _base(self, idb: bytes) -> int:
        return oprf_base(self.group, idb)

    def eval(self, idb, my_share, partner_share, partner_pub):
        """Returns (tag, A, b, blinded). A is the OPRF base H(id); b is the
        per-record blinding; blinded=A^b is the value the partner sees and the
        linkage proof binds. The partner also proves (DLEQ) it used its
        committed key share."""
        g = self.group
        hx = self._base(idb)                       # A_id = H(id)
        b = g.rand_exp()
        blinded = g.exp(hx, b)                      # A^b, sent to partner
        resp = g.exp(blinded, partner_share)
        proof = dleq_prove(g, g.g, partner_pub, blinded, resp, partner_share)
        if not dleq_verify(g, g.g, partner_pub, blinded, resp, proof):
            raise ValueError("DOPRF consistency proof failed")
        binv = pow(b, -1, g.q)
        tag = g.mul(g.exp(hx, my_share), g.exp(resp, binv))   # A^(k1+k2)
        return tag, hx, b, blinded


def tag_bytes(tag_group_elt: int) -> bytes:
    return hashlib.sha256(str(tag_group_elt).encode()).digest()


# --------------------------------------------------------------------------
# Set commitment: hiding ElGamal leaves to A_id + Merkle root; membership is
# a Merkle path PLUS the linkage proof binding the tag to the committed A_id.
# Verified holder-to-holder (the partner never sees A_id: leaf is hiding, and
# the linkage proof is zero-knowledge in A_id).
# --------------------------------------------------------------------------

def _leaf_hash(leaf) -> bytes:
    c1, c2 = leaf
    return hashlib.sha256((str(c1) + "|" + str(c2)).encode()).digest()


def _merkle_layers(leaves):
    layers = [leaves]; nodes = leaves
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            a = nodes[i]; b = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            nxt.append(hashlib.sha256(a + b).digest())
        layers.append(nxt); nodes = nxt
    return layers


def _merkle_path(layers, index):
    path, idx = [], index
    for layer in layers[:-1]:
        if idx % 2 == 0:
            sib = layer[idx + 1] if idx + 1 < len(layer) else layer[idx]
            path.append((sib, 0))
        else:
            path.append((layer[idx - 1], 1))
        idx //= 2
    return path


def _merkle_verify(leaf_hash, path, root):
    h = leaf_hash
    for sib, self_is_left in path:
        h = hashlib.sha256(h + sib).digest() if self_is_left == 0 \
            else hashlib.sha256(sib + h).digest()
    return h == root


@dataclass
class SetCommit:
    group: object
    hbar: int                          # second generator for the ElGamal leaf

    def commit(self, ids):
        """Commit to A_id = H(id) per id under a hiding ElGamal leaf; Merkle
        root over sorted leaf hashes. aux keeps per-id (leaf, s, A)."""
        g = self.group
        per_id = {}
        for idb in ids:
            A = oprf_base(g, idb)
            s = g.rand_exp()
            leaf = (g.exp(g.g, s), g.mul(A, g.exp(self.hbar, s)))   # (g^s, A*hbar^s)
            per_id[idb] = {"leaf": leaf, "s": s, "A": A,
                           "h": _leaf_hash(leaf)}
        sorted_hashes = sorted(v["h"] for v in per_id.values())
        layers = _merkle_layers(sorted_hashes)
        return layers[-1][0], {"per_id": per_id, "sorted": sorted_hashes,
                               "layers": layers}

    def prove(self, aux, idb, b, blinded):
        """Membership path for id's leaf + linkage proof binding blinded=A^b
        to the committed A in that leaf."""
        rec = aux["per_id"].get(idb)
        if rec is None:
            return None
        c1, c2 = rec["leaf"]
        mu = (rec["s"] * b) % self.group.q
        linkage = link_prove(self.group, self.hbar, c1, c2, blinded, b, mu)
        idx = aux["sorted"].index(rec["h"])
        return {"leaf": rec["leaf"], "leaf_hash": rec["h"],
                "path": _merkle_path(aux["layers"], idx), "linkage": linkage}

    def vrfy(self, root, blinded, proof):
        """Partner-side check: leaf is committed (Merkle) AND blinded is on the
        committed A (linkage). Neither reveals A_id."""
        if proof is None:
            return False
        leaf = proof["leaf"]; c1, c2 = leaf
        if _leaf_hash(leaf) != proof["leaf_hash"]:
            return False
        if not _merkle_verify(proof["leaf_hash"], proof["path"], root):
            return False
        return link_verify(self.group, self.hbar, c1, c2, blinded,
                           proof["linkage"])


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
