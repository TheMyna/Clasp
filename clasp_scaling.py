# clasp_scaling.py
# Self-driving scaling study for CLASP. No interactive input: it reads the
# sweep ranges from config.py, evaluates the model, finds the dominant term
# (bottleneck) at each scale, tests linearity, and writes a CSV.
# Run from the Clasp folder:  python3 clasp_scaling.py
import csv
import config
from clasp_model import (
    Params, communication_terms, operation_counts,
    compute_seconds, totals, bottleneck,
)


def make_params(n1, n2, B, eta_min):
    return Params(
        n1=n1, n2=n2, B=B, eta_min=eta_min,
        matches=min(n1, n2),                 # all-intersect worst case
        cH1=config.CIPHERTEXTS_PER_H1_RECORD,
        cH2=config.CIPHERTEXTS_PER_H2_RECORD,
        tags_per_record=config.TAGS_PER_RECORD,
        cret=config.CIPHERTEXTS_RETURNED_PER_SEGMENT,
        cl_ct_bytes=config.CL_CIPHERTEXT_BYTES,
        tag_bytes=config.TAG_BYTES,
        doprf_bytes=config.DOPRF_BYTES_PER_EVAL,
        partdec_bytes=config.PARTDEC_BYTES_PER_CT,
        egress_usd_per_gb=config.EGRESS_USD_PER_GB,
        cpu_usd_per_hour=config.CPU_USD_PER_HOUR,
        sec_enc=config.SEC_PER_CL_ENC, sec_add=config.SEC_PER_CL_ADD,
        sec_smul=config.SEC_PER_SCALAR_MULT, sec_dec=config.SEC_PER_THRESHOLD_DEC,
        sec_doprf=config.SEC_PER_DOPRF_EVAL,
    )


def mb(x):
    return x / 1e6


def banner(text):
    print("\n" + "=" * 72)
    print(text)
    print("=" * 72)


def timings_missing():
    return any(t is None for t in [
        config.SEC_PER_CL_ENC, config.SEC_PER_CL_ADD, config.SEC_PER_SCALAR_MULT,
        config.SEC_PER_THRESHOLD_DEC, config.SEC_PER_DOPRF_EVAL])


def notice():
    if timings_missing():
        print("\n[notice] Unit timings are None in config (unmeasured), so "
              "absolute CPU\n         time and compute cost are withheld. "
              "Operation counts and every\n         communication figure are "
              "reliable. Add timings from the BICYCL\n         harness to "
              "unlock time output.")


def study_input_size(rows_out):
    banner("STUDY 1  scaling with set size n   (B fixed = %d, eta_min = %d)"
           % (config.SWEEP_SEGMENTS_FIXED, config.ETA_MIN))
    print("%-12s %14s   %-20s %7s   %10s" %
          ("n", "total comm MB", "comm bottleneck", "share", "x vs prev"))
    print("-" * 72)
    prev = None
    for n in config.SWEEP_SET_SIZES:
        p = make_params(n, n, config.SWEEP_SEGMENTS_FIXED, config.ETA_MIN)
        t = totals(p)
        comm = communication_terms(p)
        name, _, share = bottleneck(comm)
        cur = t["total_comm_bytes"]
        ratio = "-" if prev is None else "%.2fx" % (cur / prev)
        print("%-12d %14.3f   %-20s %6.1f%%   %10s" %
              (n, mb(cur), name, share * 100, ratio))
        prev = cur
        rows_out.append({"study": "input_size", "n": n,
                         "B": config.SWEEP_SEGMENTS_FIXED,
                         "eta_min": config.ETA_MIN,
                         "total_comm_MB": mb(cur),
                         "comm_bottleneck": name,
                         "bottleneck_share": share})
    print("\nReading: 'x vs prev' near 2.00 each time inputs grow 10x would be "
          "linear\nper decade. Here each row multiplies n by 10, so linear "
          "growth shows\nas ~10x per row. Any term super-linear in n would "
          "diverge from 10x.")


def linearity_test():
    banner("STUDY 1b  linearity check (double n, expect cost to double)")
    base = config.SWEEP_FIXED_N
    p1 = make_params(base, base, config.SWEEP_SEGMENTS_FIXED, config.ETA_MIN)
    p2 = make_params(2 * base, 2 * base, config.SWEEP_SEGMENTS_FIXED,
                     config.ETA_MIN)
    c1 = totals(p1)["total_comm_bytes"]
    c2 = totals(p2)["total_comm_bytes"]
    print("n = %d  -> %.3f MB" % (base, mb(c1)))
    print("n = %d  -> %.3f MB" % (2 * base, mb(c2)))
    print("ratio cost(2n)/cost(n) = %.4f  (1.0000 would be n-independent, "
          "2.0000 exactly linear)" % (c2 / c1))
    print("It sits just under 2.0 because the B-driven return term does not "
          "grow with n.")


def study_segments(rows_out):
    banner("STUDY 2  scaling with segments B   (n fixed = %d, eta_min = %d)"
           % (config.SWEEP_FIXED_N, config.ETA_MIN))
    print("%-10s %14s   %14s   %-20s" %
          ("B", "total comm MB", "S->H return MB", "comm bottleneck"))
    print("-" * 72)
    for B in config.SWEEP_SEGMENT_COUNTS:
        p = make_params(config.SWEEP_FIXED_N, config.SWEEP_FIXED_N, B,
                        config.ETA_MIN)
        t = totals(p)
        comm = communication_terms(p)
        name, _, _ = bottleneck(comm)
        print("%-10d %14.3f   %14.4f   %-20s" %
              (B, mb(t["total_comm_bytes"]), mb(comm["S->H return"]), name))
        rows_out.append({"study": "segments", "n": config.SWEEP_FIXED_N, "B": B,
                         "eta_min": config.ETA_MIN,
                         "total_comm_MB": mb(t["total_comm_bytes"]),
                         "comm_bottleneck": name, "bottleneck_share": ""})
    print("\nReading: total barely moves with B while the n-driven uploads "
          "dominate.\nSegmentation is near-free until B approaches n. This is "
          "the scalability\nargument for per-segment output.")


def study_sentinels(rows_out):
    banner("STUDY 3  sentinel crossover   (n fixed = %d, B fixed = %d)"
           % (config.SWEEP_FIXED_N, config.SWEEP_SEGMENTS_FIXED))
    print("%-10s %12s %14s   %-22s" %
          ("eta_min", "E=B*eta", "total comm MB", "note"))
    print("-" * 72)
    for eta in config.SWEEP_ETA_MIN_VALUES:
        p = make_params(config.SWEEP_FIXED_N, config.SWEEP_FIXED_N,
                        config.SWEEP_SEGMENTS_FIXED, eta)
        t = totals(p)
        E = p.E
        note = "E is %.1f%% of n" % (100.0 * E / config.SWEEP_FIXED_N)
        print("%-10d %12d %14.3f   %-22s" %
              (eta, E, mb(t["total_comm_bytes"]), note))
        rows_out.append({"study": "sentinels", "n": config.SWEEP_FIXED_N,
                         "B": config.SWEEP_SEGMENTS_FIXED, "eta_min": eta,
                         "total_comm_MB": mb(t["total_comm_bytes"]),
                         "comm_bottleneck": "", "bottleneck_share": ""})
    print("\nReading: sentinels are cheap until B*eta_min rivals n. With many "
          "small\nsegments the floor dominates, the regime where DP matters "
          "most. Surface\nthis tension in the paper rather than hiding it.")


def operation_profile():
    banner("OPERATION COUNTS at n = %d, B = %d (which op is most numerous)"
           % (config.SWEEP_FIXED_N, config.SWEEP_SEGMENTS_FIXED))
    p = make_params(config.SWEEP_FIXED_N, config.SWEEP_FIXED_N,
                    config.SWEEP_SEGMENTS_FIXED, config.ETA_MIN)
    counts = operation_counts(p)
    for name, val in sorted(counts.items(), key=lambda kv: -kv[1]):
        print("  %-24s %15d" % (name, val))
    secs = compute_seconds(p)
    if secs is None:
        print("\n  Predicted seconds: withheld (timings unmeasured).")
    else:
        # Name any operation whose unit timing is 0.0, i.e. excluded because
        # it was not benchmarked, so the total is never read as complete.
        excluded = []
        if not config.SEC_PER_SCALAR_MULT:
            excluded.append("scalar-mult")
        if not config.SEC_PER_DOPRF_EVAL:
            excluded.append("DOPRF")
        note = ""
        if excluded:
            note = "  [excludes %s (unmeasured)]" % ", ".join(excluded)
        name, val, share = bottleneck(secs)
        print("\n  Predicted single-core CPU-seconds: %.2f%s"
              % (sum(secs.values()), note))
        print("  Time bottleneck: %s (%.1f%% of counted CPU time)" %
              (name, share * 100))


def write_csv(rows):
    path = "scaling_results.csv"
    fields = ["study", "n", "B", "eta_min", "total_comm_MB",
              "comm_bottleneck", "bottleneck_share"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print("\nWrote %s (open it in Numbers or Excel)." % path)


def main():
    print("CLASP scaling study. Inputs are driven from config.py, not typed.")
    notice()
    rows = []
    study_input_size(rows)
    linearity_test()
    study_segments(rows)
    study_sentinels(rows)
    operation_profile()
    write_csv(rows)


if __name__ == "__main__":
    main()  