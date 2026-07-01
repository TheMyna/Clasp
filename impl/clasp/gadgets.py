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
# Chaum-Pedersen DLEQ over the prime-order group (Fiat-Shamir).
# Proves log_{base1}(pub1) == log_{base2}(pub2) in zero knowledge of x.
# --------------------------------------------------------------------------

def _dleq_challenge(group, *elems):
    h = hashlib.sha256()
    for e in elems:
        h.update(str(e).encode())
    return int.from_bytes(h.digest(), "big") % group.q


def dleq_prove(group, base1, pub1, base2, pub2, x):
    g = group
    r = g.rand_exp()
    A1 = g.exp(base1, r); A2 = g.exp(base2, r)
    c = _dleq_challenge(g, base1, pub1, base2, pub2, A1, A2)
    z = (r + c * x) % g.q
    return (c, z)


def dleq_verify(group, base1, pub1, base2, pub2, proof):
    g = group
    c, z = proof
    A1 = g.mul(g.exp(base1, z), g.exp(g.inv(pub1), c))
    A2 = g.mul(g.exp(base2, z), g.exp(g.inv(pub2), c))
    return _dleq_challenge(g, base1, pub1, base2, pub2, A1, A2) == c

# --------------------------------------------------------------------------
# Distributed OPRF
# --------------------------------------------------------------------------

@dataclass
class DOPRF:
    group: Group
    k1: int      # holder 1 share
    k2: int      # holder 2 share
    K1: int = None   # g^k1, public commitment to share 1
    K2: int = None   # g^k2, public commitment to share 2

    @classmethod
    def share(cls, group: Group) -> "DOPRF":
        k1 = group.rand_exp(); k2 = group.rand_exp()
        return cls(group=group, k1=k1, k2=k2,
                   K1=group.exp(group.g, k1), K2=group.exp(group.g, k2))

    def _base(self, idb: bytes) -> int:
        return self.group.hash_to_group(b"OPRF" + idb)

    def eval(self, idb: bytes, my_share: int, partner_share: int,
             partner_pub: int) -> int:
        """Holder with `my_share` evaluates F_k on its own id; partner applies
        `partner_share` and proves it used the committed share (DLEQ), seeing
        only a blinded random element."""
        g = self.group
        hx = self._base(idb)
        b = g.rand_exp()
        blinded = g.exp(hx, b)                 # sent to partner (looks random)
        # --- partner side: apply share and PROVE consistency with partner_pub ---
        resp = g.exp(blinded, partner_share)
        proof = dleq_prove(g, g.g, partner_pub, blinded, resp, partner_share)
        # --- back on my side: VERIFY before using (abort on failure) ---
        if not dleq_verify(g, g.g, partner_pub, blinded, resp, proof):
            raise ValueError("DOPRF consistency proof failed: partner did not "
                             "use its committed key share")
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


def _merkle_layers(leaves):
    """leaves: sorted list of leaf-hash bytes. Returns layers; last is [root]."""
    layers = [leaves]
    nodes = leaves
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            a = nodes[i]
            b = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            nxt.append(hashlib.sha256(a + b).digest())
        layers.append(nxt)
        nodes = nxt
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


def _merkle_verify(leaf, path, root):
    h = leaf
    for sib, self_is_left in path:
        h = hashlib.sha256(h + sib).digest() if self_is_left == 0 \
            else hashlib.sha256(sib + h).digest()
    return h == root


@dataclass
class SetCommit:
    """Commit-to-the-tag set commitment. The leaf is H(tag); the Merkle root
    binds the holder to its epoch tag set. Membership is a real Merkle path,
    verified by the aggregator (which already sees the tags), so a holder
    cannot present a tag outside its committed set. [Replaces the earlier
    ElGamal-leaf / ZK-in-tag design; see the back:commit paragraph.]"""
    group: object = None    # kept for interface compatibility; unused here

    def commit(self, tags):
        leaf_of = {t: hashlib.sha256(t).digest() for t in tags}
        leaves = sorted(leaf_of.values())
        layers = _merkle_layers(leaves)
        return layers[-1][0], {"layers": layers, "leaves": leaves,
                               "leaf_of": leaf_of}

    def prove(self, aux, tag):
        leaf = aux["leaf_of"].get(tag)
        if leaf is None:
            return None
        idx = aux["leaves"].index(leaf)
        return {"leaf": leaf, "path": _merkle_path(aux["layers"], idx)}

    def vrfy(self, root, tag, proof):
        if proof is None or proof["leaf"] != hashlib.sha256(tag).digest():
            return False
        return _merkle_verify(proof["leaf"], proof["path"], root)


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
