# clasp_model.py
# Pure CLASP cost model. No I/O. Every number arrives via Params; nothing
# about cost is baked into this file.
from __future__ import annotations   # lets 'float | None' work on Python 3.9
from dataclasses import dataclass


@dataclass
class Params:
    n1: int
    n2: int
    B: int
    eta_min: int
    matches: int
    cH1: int
    cH2: int
    tags_per_record: int
    cret: int
    cl_ct_bytes: float
    tag_bytes: float
    doprf_bytes: float
    partdec_bytes: float
    egress_usd_per_gb: float
    cpu_usd_per_hour: float
    sec_enc: float | None
    sec_add: float | None
    sec_smul: float | None
    sec_dec: float | None
    sec_doprf: float | None

    @property
    def E(self) -> int:
        return self.B * self.eta_min


def communication_terms(p: Params) -> dict:
    """Bytes per additive communication term. Depends only on sizes, so this
    is reliable now, before any implementation exists."""
    E = p.E
    return {
        "H1->S ciphertexts": (p.n1 + E) * p.cH1 * p.cl_ct_bytes,
        "H1->S tags":        (p.n1 + E) * p.tags_per_record * p.tag_bytes,
        "H2->S ciphertexts": (p.n2 + E) * p.cH2 * p.cl_ct_bytes,
        "H2->S tags":        (p.n2 + E) * p.tags_per_record * p.tag_bytes,
        "S->H return":       p.B * p.cret * p.cl_ct_bytes,
        "H<->H DOPRF":       ((p.n1 + E) + (p.n2 + E)) * p.doprf_bytes,
        "H<->H decryption":  (p.cret * p.B) * p.partdec_bytes,
    }


def operation_counts(p: Params) -> dict:
    """Exact operation counts, totals across parties."""
    E = p.E
    return {
        "CL encryptions":        p.cH1 * (p.n1 + E) + p.cH2 * (p.n2 + E),
        "DOPRF evaluations":     (p.n1 + E) + (p.n2 + E),
        "Server hom-additions":  (p.cH1 + p.cH2) * (p.matches + E),
        "Server scalar-mults":   p.B,
        "Threshold decryptions": p.cret * p.B,
    }


def compute_seconds(p: Params):
    """Predicted CPU-seconds per operation class, or None if any unit timing
    is unmeasured. We refuse to invent timings."""
    timings = [p.sec_enc, p.sec_add, p.sec_smul, p.sec_dec, p.sec_doprf]
    if any(t is None for t in timings):
        return None
    c = operation_counts(p)
    return {
        "CL encryptions":        p.sec_enc * c["CL encryptions"],
        "DOPRF evaluations":     p.sec_doprf * c["DOPRF evaluations"],
        "Server hom-additions":  p.sec_add * c["Server hom-additions"],
        "Server scalar-mults":   p.sec_smul * c["Server scalar-mults"],
        "Threshold decryptions": p.sec_dec * c["Threshold decryptions"],
    }


def totals(p: Params) -> dict:
    comm = communication_terms(p)
    total_comm = sum(comm.values())
    egress_usd = (total_comm / 1e9) * p.egress_usd_per_gb
    secs = compute_seconds(p)
    if secs is None:
        total_secs, compute_usd = None, None
        total_usd = egress_usd
    else:
        total_secs = sum(secs.values())
        compute_usd = (total_secs / 3600.0) * p.cpu_usd_per_hour
        total_usd = egress_usd + compute_usd
    return {
        "total_comm_bytes": total_comm,
        "egress_usd": egress_usd,
        "total_cpu_seconds": total_secs,
        "compute_usd": compute_usd,
        "total_usd": total_usd,
    }


def bottleneck(terms: dict):
    """(name, value, share) of the largest additive term."""
    total = sum(terms.values())
    if total == 0:
        return (None, 0, 0.0)
    name, value = max(terms.items(), key=lambda kv: kv[1])
    return (name, value, value / total)