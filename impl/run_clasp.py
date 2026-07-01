"""
End-to-end CLASP run in one process.

  1. generate synthetic (advertising or genomic) data with a known intersection
  2. run Setup -> Tag -> Aggregate -> Release
  3. verify the released (count, sum) equal the cleartext ground truth
  4. demonstrate a malicious server being caught (forgery)
  5. report per-phase wall-clock

Usage:
  python3 run_clasp.py --n 200 --segments 4 --scenario ads
  python3 run_clasp.py --n 200 --segments 4 --scenario genomic
"""
import argparse, secrets, time
from clasp.crypto import gen_group, PaillierTAHE
from clasp.protocol import Clasp, Params


def gen_data(n, B, overlap, rho_max, scenario):
    """Return (U1_vals: id->rho), (U2_seg: id->segment), and ground truth."""
    common = [secrets.token_bytes(8) for _ in range(int(n * overlap))]
    only1 = [secrets.token_bytes(8) for _ in range(n - len(common))]
    only2 = [secrets.token_bytes(8) for _ in range(n - len(common))]
    U1_vals, U2_seg = {}, {}
    for idb in common + only1:
        U1_vals[idb] = 1 + secrets.randbelow(rho_max)
    for idb in common + only2:
        U2_seg[idb] = 1 + secrets.randbelow(B)
    # ground truth: per-segment count and sum over the true intersection
    gt = {b: [0, 0] for b in range(1, B + 1)}
    for idb in common:
        b = U2_seg[idb]
        gt[b][0] += 1
        gt[b][1] += U1_vals[idb]
    return U1_vals, U2_seg, {b: tuple(v) for b, v in gt.items()}


def forge_demonstrations(proto, U1_vals):
    """Show the malicious-security proofs reject forgery end-to-end."""
    import secrets as _s
    from clasp.gadgets import oprf_base
    g = proto.g

    # (1) DOPRF consistency: partner claims a key share other than committed.
    some_id = next(iter(U1_vals))
    try:
        proto.doprf.eval(some_id, proto.doprf.k1, proto.doprf.k2, proto.doprf.K1)
        d = "MISSED"
    except ValueError:
        d = "caught"
    print("FORGE (DOPRF consistency, mismatched key share) ->", d)

    # (2) inject a tag on a NON-committed id: blinded on A' != committed A.
    real_id = next(iter(U1_vals))
    outsider = b"NOT_A_MEMBER_" + _s.token_bytes(6)
    Ap = oprf_base(g, outsider); b = g.rand_exp(); blinded_bad = g.exp(Ap, b)
    proof = proto.sc.prove(proto.aux1, real_id, b, blinded_bad)
    caught = (proof is None) or (not proto.sc.vrfy(proto.com1, blinded_bad, proof))
    print("FORGE (inject non-committed id, linkage) ->",
          "caught" if caught else "MISSED")

    # (3) outsider has no committed leaf at all.
    none_proof = proto.sc.prove(proto.aux1, outsider, b, blinded_bad)
    print("FORGE (outsider has no committed leaf) ->",
          "caught" if none_proof is None else "MISSED")

    # (4) tamper the Merkle path of an honest proof.
    tag, A, bb, blinded = proto.doprf.eval(real_id, proto.doprf.k1,
                                           proto.doprf.k2, proto.doprf.K2)
    good = proto.sc.prove(proto.aux1, real_id, bb, blinded)
    bad = dict(good)
    bad["path"] = [(_s.token_bytes(32), sdir) for (_, sdir) in good["path"]]
    print("FORGE (tampered Merkle path) ->",
          "caught" if not proto.sc.vrfy(proto.com1, blinded, bad) else "MISSED")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--segments", type=int, default=4)
    ap.add_argument("--overlap", type=float, default=0.5)
    ap.add_argument("--rho_max", type=int, default=100)
    ap.add_argument("--scenario", choices=["ads", "genomic"], default="ads")
    ap.add_argument("--key_bits", type=int, default=1024)
    ap.add_argument("--backend", choices=["paillier", "bicycl"],
                    default="paillier",
                    help="paillier = in-sandbox reference; "
                         "bicycl = real class-group CL-HSMqk")
    args = ap.parse_args()

    print(f"CLASP end-to-end  |  scenario={args.scenario}  n={args.n}  "
          f"B={args.segments}  overlap={args.overlap}  backend={args.backend}")

    U1_vals, U2_seg, gt = gen_data(args.n, args.segments, args.overlap,
                                   args.rho_max, args.scenario)

    t0 = time.perf_counter()
    if args.backend == "bicycl":
        # real class-group backend from the BICYCL bridge
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "..", "bicycl_bridge"))
        from clbackend import BICYCLBackend
        ahe = BICYCLBackend(sec_bits=128)
        q = ahe.plaintext_modulus              # real CL cleartext_bound (256-bit)
        # bands sized for a 256-bit field: L + log2(G) + log2(N) < 256
        L, G = 128, 2 ** 80
        print("[backend: real class-group CL-HSMqk at 128-bit; real 2-of-2 "
              "threshold decryption, DOPRF consistency (DLEQ), and "
              "commit-to-A_id membership+linkage, all verified]\n")
    else:
        group_q = 2 ** 256 - 189               # 256-bit-ish prime field
        ahe = PaillierTAHE(args.key_bits)
        q, L, G = group_q, 40, 2 ** 128
        print("[backend: threshold Paillier + mod-p group; "
              "malicious proofs stubbed]\n")
    group = gen_group(256)
    params = Params(q=q, L=L, G=G, rho_max=args.rho_max,
                    eps_out=1.0, eps_srv=1.0, eta_min=5)
    setup_prep = time.perf_counter() - t0

    proto = Clasp(group, ahe, params)
    proto.setup(list(U1_vals.keys()), U2_seg, args.segments)
    h1 = proto.tag_H1(U1_vals)
    h2 = proto.tag_H2(U2_seg)
    agg = proto.aggregate(h1, h2)
    results, aborts = proto.release(agg)

    # ---- correctness against cleartext ground truth ----
    print("segment |  true (c,s)  | recovered (c,s) | match | noised (c,s)")
    ok = True
    for b in range(1, args.segments + 1):
        tc, ts = gt[b]
        if results[b] is None:
            print(f"  {b:4}  |  {tc:3},{ts:5}  |   aborted: {aborts.get(b)}")
            ok = False; continue
        cn, sn, ct, st = results[b]
        good = (ct == tc and st == ts)
        ok = ok and good
        print(f"  {b:4}  |  {tc:3},{ts:5}  |    {ct:3},{st:5}    | "
              f"{'OK ' if good else 'BAD'}  |  {cn:3},{sn:5}")
    print("\nCORRECTNESS:", "PASS (recovered == ground truth)" if ok else "FAIL")

    # ---- malicious server: forge one sum, show it is caught ----
    b0 = next(b for b in agg if agg[b] is not None)
    s_ct, as_ct, c_ct, ac_ct = agg[b0]
    forged = (ahe.add(s_ct, ahe.enc(999)), as_ct, c_ct, ac_ct)  # tamper sum only
    proto2 = Clasp(group, ahe, params)
    proto2.__dict__.update(proto.__dict__)          # reuse keys/eta
    _, ab = proto2.release({b0: forged})
    print(f"TAMPER TEST: forged sum in segment {b0} -> "
          f"{'caught (' + ab.get(b0, 'MISSED') + ')' if ab.get(b0) else 'MISSED'}")

    forge_demonstrations(proto, U1_vals)

    # ---- timing ----
    print("\nper-phase wall-clock (s):")
    print(f"  key/group prep : {setup_prep:8.3f}")
    print(f"  Setup          : {proto.t.setup:8.3f}")
    print(f"  Tag            : {proto.t.tag:8.3f}")
    print(f"  Aggregate      : {proto.t.aggregate:8.3f}")
    print(f"  Release        : {proto.t.release:8.3f}")
    total = setup_prep + proto.t.setup + proto.t.tag + proto.t.aggregate + proto.t.release
    print(f"  TOTAL          : {total:8.3f}")


if __name__ == "__main__":
    main()
