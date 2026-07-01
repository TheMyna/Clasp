# GPL-3.0-or-later. Links BICYCL via clbicycl (see NOTICE).
# Stage-one CLASP CL backend: real class-group enc/add/scal/dec.
# [STAGE-ONE LIMIT] Single keypair, so part_dec/fin_dec wrap single-key
# decrypt as a placeholder. Stage two binds CL_Threshold_Static for the
# real 2-of-2 threshold decryption with proofs.
import clbicycl


class BICYCLBackend:
    """ThresholdAHE over real class-group ciphertexts (CL-HSMqk, 128-bit).

    CL plaintext space is F_q with q a 256-bit prime (measured: values up to
    2^255 round-trip; 2^256 is rejected; 2^255+2^255 wraps). Every value handed
    to enc MUST already be reduced below q, so the protocol reduces the MAC
    (alpha*rho) modulo q in Python before encryption, and the bands are sized
    so the accumulated payload never crosses q.
    """
    def __init__(self, sec_bits: int = 128, q: int = None):
        self.ctx = clbicycl.ClContext(sec_bits)
        # q is the CL field order. If not supplied, use the measured 256-bit
        # bound; the protocol must pass the exact q so band checks are correct.
        # read the true CL field bound from the context
        self._q = int(self.ctx.cleartext_bound()) if q is None else q

    @property
    def plaintext_modulus(self) -> int:
        return self._q

    def enc(self, m: int):
        return self.ctx.enc(str(int(m) % self._q))

    def add(self, c1, c2):
        # re-randomizing add (fresh r): use for the final released ciphertext
        return self.ctx.add(c1, c2)

    def add_fast(self, c1, c2):
        # non-re-randomizing add (bare composition): use for partial sums that
        # are never revealed; caller re-randomizes the final ciphertext once
        return self.ctx.add_norand(c1, c2)

    def scalar_mul(self, a: int, c):
        return self.ctx.scal(c, str(int(a) % self._q))

    def refresh(self, c):
        return self.ctx.add(c, self.ctx.enc("0"))

    def part_dec(self, share_id: int, c):
        # [STAGE-ONE PLACEHOLDER] no real threshold yet.
        return (share_id, c)

    def fin_dec(self, c, partials):
        # [STAGE-ONE PLACEHOLDER] single-key decrypt via the context.
        _, ct = partials[0]
        return int(self.ctx.dec(ct))
