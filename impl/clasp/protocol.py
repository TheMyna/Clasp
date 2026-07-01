"""
CLASP protocol: the four algorithms Setup, Tag, Aggregate, Release, wired
into a single-process end-to-end run. Produces the per-segment count and sum
over the intersection, verifies the three integrity checks, and applies the
two DP mechanisms. Timings are collected per phase.

Roles: H1 holds (id -> value rho); H2 holds (id -> segment b). S matches and
aggregates on ciphertexts, never decrypts.
"""
from __future__ import annotations
import time, secrets
from dataclasses import dataclass, field
from .crypto import Group, ThresholdAHE
from .gadgets import (DOPRF, SetCommit, tag_bytes, mac, g_kappa,
                      geometric_ge0, discrete_laplace)


@dataclass
class Params:
    q: int                     # MAC / binding field prime
    L: int                     # payload lift (low band width in bits)
    G: int                     # binding range bound
    rho_max: int
    eps_out: float
    eps_srv: float
    eta_min: int


@dataclass
class Timings:
    setup: float = 0.0
    tag: float = 0.0
    aggregate: float = 0.0
    release: float = 0.0


class Clasp:
    def __init__(self, group: Group, ahe: ThresholdAHE, params: Params):
        self.g = group
        self.ahe = ahe
        self.p = params
        self.t = Timings()

    # ---- Phase 1: Setup (once per epoch) --------------------------------
    def setup(self, U1_ids, U2_seg, B):
        s = time.perf_counter()
        self.B = B
        self.doprf = DOPRF.share(self.g)
        self.h2 = self.g.exp(self.g.g, self.g.rand_exp())     # 2nd generator
        self.sc = SetCommit(self.g, self.h2)
        self.alpha = 1 + secrets.randbelow(self.p.q - 1)
        self.kappa = secrets.token_bytes(16)
        # server-cardinality DP: draw sentinel count per segment, plant in both
        self.eta = {}
        self.sentinels = {}
        for b in range(1, B + 1):
            self.eta[b] = self.p.eta_min + geometric_ge0(self.p.eps_srv)
            self.sentinels[b] = [secrets.token_bytes(8) for _ in range(self.eta[b])]
        # commitments to the (real) input sets
        self.com1, self.aux1 = self.sc.commit(sorted(U1_ids))
        self.com2, self.aux2 = self.sc.commit(sorted(U2_seg.keys()))
        self.Lambda = 0.0
        self.t.setup += time.perf_counter() - s

    # ---- Phase 2: Tag and outsource -------------------------------------
    def _tag(self, idb, owner_share, partner_share):
        elt = self.doprf.eval(idb, owner_share, partner_share)
        return tag_bytes(elt)

    def tag_H1(self, U1_vals):
        """H1: for each id, upload (t, [rho+g*2^L], [alpha*rho], [1+g*2^L], [alpha])."""
        s = time.perf_counter()
        lift = 1 << self.p.L
        store = []
        items = list(U1_vals.items()) + [(sid, 0) for b in self.sentinels
                                          for sid in self.sentinels[b]]
        for idb, rho in items:
            t = self._tag(idb, self.doprf.k1, self.doprf.k2)
            self.sc.prove(self.aux1, 0)                    # membership proof (stub vrfy)
            gt = g_kappa(self.kappa, t, self.p.G)
            store.append((
                t,
                self.ahe.enc(rho + gt * lift),            # sum payload
                self.ahe.enc(mac(self.alpha, rho, self.p.q)),
                self.ahe.enc(1 + gt * lift),              # count payload
                self.ahe.enc(self.alpha),
            ))
        secrets.SystemRandom().shuffle(store)
        self.t.tag += time.perf_counter() - s
        return store

    def tag_H2(self, U2_seg):
        """H2: per id, append (t, [-g]) to its segment list."""
        s = time.perf_counter()
        seglists = {b: [] for b in range(1, self.B + 1)}
        items = list(U2_seg.items())
        for b in self.sentinels:
            for sid in self.sentinels[b]:
                items.append((sid, b))
        for idb, b in items:
            t = self._tag(idb, self.doprf.k2, self.doprf.k1)
            self.sc.prove(self.aux2, 0)
            gt = g_kappa(self.kappa, t, self.p.G)
            seglists[b].append((t, self.ahe.enc((-gt) % self.ahe.plaintext_modulus)))
        for b in seglists:
            secrets.SystemRandom().shuffle(seglists[b])
        self.t.tag += time.perf_counter() - s
        return seglists

    # ---- Phase 3: Aggregate (server; only add and public-scalar-mul) ----
    def aggregate(self, h1_store, h2_seglists):
        s = time.perf_counter()
        lift = 1 << self.p.L
        h1_by_tag = {row[0]: row for row in h1_store}
        out = {}
        for b, lst in h2_seglists.items():
            matched = [(t, negc) for (t, negc) in lst if t in h1_by_tag]
            if not matched:
                out[b] = None
                continue
            # residue R_b = 2^L (+) sum of matched -g   [scalar-mul then add]
            R = self.ahe.enc(0)
            for _, negc in matched:
                R = self.ahe.add(R, negc)
            R = self.ahe.scalar_mul(lift, R)
            s_ct = self.ahe.enc(0); as_ct = self.ahe.enc(0)
            c_ct = self.ahe.enc(0); ac_ct = self.ahe.enc(0)
            for t, _ in matched:
                _, sump, macp, cntp, alp = h1_by_tag[t]
                s_ct = self.ahe.add(s_ct, sump)
                as_ct = self.ahe.add(as_ct, macp)
                c_ct = self.ahe.add(c_ct, cntp)
                ac_ct = self.ahe.add(ac_ct, alp)
            s_ct = self.ahe.refresh(self.ahe.add(s_ct, R))
            c_ct = self.ahe.refresh(self.ahe.add(c_ct, R))
            out[b] = (s_ct, self.ahe.refresh(as_ct),
                      c_ct, self.ahe.refresh(ac_ct))
        self.t.aggregate += time.perf_counter() - s
        return out

    # ---- Phase 4: Verify and Release ------------------------------------
    def _dec(self, c):
        return self.ahe.fin_dec(c, [self.ahe.part_dec(1, c), self.ahe.part_dec(2, c)])

    def release(self, agg):
        s = time.perf_counter()
        lift = 1 << self.p.L
        results, aborts = {}, {}
        for b, quad in agg.items():
            if quad is None:
                results[b] = None
                continue
            s_ct, as_ct, c_ct, ac_ct = quad
            s_hat = self._dec(s_ct); as_hat = self._dec(as_ct)
            c_hat = self._dec(c_ct); ac_hat = self._dec(ac_ct)
            s_low, s_hi = s_hat % lift, s_hat // lift
            c_low, c_hi = c_hat % lift, c_hat // lift
            # binding check (injection)
            if s_hi != 0 or c_hi != 0:
                aborts[b] = "injection"; results[b] = None; continue
            # authentication check (forgery)
            if as_hat % self.p.q != mac(self.alpha, s_low, self.p.q) or \
               ac_hat % self.p.q != mac(self.alpha, c_low, self.p.q):
                aborts[b] = "forgery"; results[b] = None; continue
            # sentinel check (omission): sentinels carry rho=0, count=1 each
            if c_low < self.eta[b]:
                aborts[b] = "omission"; results[b] = None; continue
            # subtract sentinel contribution (eta_b count, 0 sum)
            c_true = c_low - self.eta[b]
            s_true = s_low
            # output DP
            c_noised = c_true + discrete_laplace(self.p.eps_out, 1)
            s_noised = s_true + discrete_laplace(self.p.eps_out, self.p.rho_max)
            self.Lambda += self.p.eps_out
            results[b] = (c_noised, s_noised, c_true, s_true)
        self.t.release += time.perf_counter() - s
        return results, aborts
