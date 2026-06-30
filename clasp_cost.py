#!/usr/bin/env python3
"""
CLASP analytical cost calculator.

This computes communication, operation counts, and monetary cost for the
CLASP protocol from parameters that YOU supply. It does not measure a real
implementation and it hardcodes no costs: every size, count, price, and
(optional) unit timing is read from your input, so the output is exactly the
complexity model evaluated on your numbers.

Run from the Clasp folder with:  python3 clasp_cost.py
"""


# ---- small input helpers that re-ask on bad input -------------------------

def ask_int(prompt, minimum=0):
    while True:
        raw = input(prompt + " ").strip()
        try:
            value = int(raw)
            if value < minimum:
                print(f"  Please enter an integer >= {minimum}.")
                continue
            return value
        except ValueError:
            print("  Please enter a whole number.")


def ask_float(prompt, minimum=0.0):
    while True:
        raw = input(prompt + " ").strip()
        try:
            value = float(raw)
            if value < minimum:
                print(f"  Please enter a number >= {minimum}.")
                continue
            return value
        except ValueError:
            print("  Please enter a number (decimals allowed).")


def ask_yes_no(prompt):
    while True:
        raw = input(prompt + " (y/n) ").strip().lower()
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("  Please answer y or n.")


# ---- main ------------------------------------------------------------------

def main():
    print("=" * 64)
    print("CLASP analytical cost calculator")
    print("All numbers come from you. Nothing is hardcoded.")
    print("=" * 64)

    # Set sizes and structure.
    print("\n-- Inputs: set sizes and protocol structure --")
    n1 = ask_int("H1 (vendor) set size |U1|:", 0)
    n2 = ask_int("H2 (network) set size w = |U2|:", 0)
    B = ask_int("Number of segments B:", 1)
    E = ask_int("Total sentinel records across all segments E "
                "(e.g. B * eta_min):", 0)

    print("\n-- Inputs: how many objects each record carries --")
    print("(CLASP as written: H1 uploads 4 ciphertexts, H2 uploads 1, "
          "1 tag each, server returns 4 per segment.)")
    cH1 = ask_int("Ciphertexts per H1 record:", 0)
    cH2 = ask_int("Ciphertexts per H2 record:", 0)
    tg = ask_int("Tags per record:", 0)
    cret = ask_int("Ciphertexts returned by server per segment:", 0)

    print("\n-- Inputs: element sizes in bytes --")
    cb = ask_float("One class-group (CL) ciphertext, bytes:", 0)
    tb = ask_float("One tag, bytes:", 0)

    print("\n-- Inputs: intersection size --")
    print(f"(Worst case all-intersect = the smaller set = {min(n1, n2)}.)")
    matches = ask_int("Number of matched records (intersection size):", 0)

    # Communication, byte by byte, per channel.
    h1_to_s = (n1 + E) * (cH1 * cb + tg * tb)
    h2_to_s = (n2 + E) * (cH2 * cb + tg * tb)
    s_to_h = B * cret * cb

    # Optional holder-to-holder channel (needs sizes you may not have yet).
    hh_total = 0.0
    have_hh = ask_yes_no(
        "\nDo you have sizes for the holder-to-holder channel "
        "(DOPRF + decryption)?")
    if have_hh:
        doprf_bytes = ask_float("Bytes per DOPRF evaluation (with proof):", 0)
        partdec_bytes = ask_float(
            "Bytes per returned ciphertext for partial decryption "
            "(with proof):", 0)
        doprf_evals = (n1 + E) + (n2 + E)
        hh_doprf = doprf_evals * doprf_bytes
        hh_dec = (cret * B) * partdec_bytes
        hh_total = hh_doprf + hh_dec

    total_comm = h1_to_s + h2_to_s + s_to_h + hh_total

    # Operation counts (totals across parties), from the complexity model.
    cl_encryptions = cH1 * (n1 + E) + cH2 * (n2 + E)
    doprf_evaluations = (n1 + E) + (n2 + E)
    server_hom_adds = (cH1 + cH2) * (matches + E)
    server_scalar_mults = B
    threshold_decryptions = cret * B
    partial_decryptions = 2 * cret * B
    decryption_proofs = cret * B

    # Monetary: egress.
    print("\n-- Inputs: cloud prices --")
    price_per_gb = ask_float("Egress price, USD per GB:", 0)
    egress_gb = total_comm / 1e9
    egress_cost_usd = egress_gb * price_per_gb

    # Monetary: compute (optional, needs unit timings).
    compute_cost_usd = 0.0
    cpu_seconds = 0.0
    have_timings = ask_yes_no(
        "\nDo you have measured unit timings (seconds per operation)?")
    if have_timings:
        t_enc = ask_float("Seconds per CL encryption:", 0)
        t_add = ask_float("Seconds per CL homomorphic addition:", 0)
        t_smul = ask_float("Seconds per public-scalar multiplication:", 0)
        t_dec = ask_float("Seconds per threshold decryption (with proof):", 0)
        t_doprf = ask_float("Seconds per DOPRF evaluation:", 0)
        price_per_cpu_hr = ask_float("CPU price, USD per hour:", 0)
        cpu_seconds = (t_enc * cl_encryptions
                       + t_add * server_hom_adds
                       + t_smul * server_scalar_mults
                       + t_dec * threshold_decryptions
                       + t_doprf * doprf_evaluations)
        compute_cost_usd = (cpu_seconds / 3600.0) * price_per_cpu_hr

    total_cost_usd = egress_cost_usd + compute_cost_usd

    # ---- report ----
    mb = 1e6
    print("\n" + "=" * 64)
    print("RESULTS")
    print("=" * 64)

    print("\nOperation counts (totals across parties):")
    print(f"  CL encryptions          : {cl_encryptions}")
    print(f"  DOPRF evaluations       : {doprf_evaluations}")
    print(f"  Server hom. additions   : {server_hom_adds}")
    print(f"  Server scalar mults     : {server_scalar_mults}")
    print(f"  Threshold decryptions   : {threshold_decryptions}")
    print(f"  Partial decryptions     : {partial_decryptions}")
    print(f"  Decryption proofs       : {decryption_proofs}")

    print("\nCommunication (MB):")
    print(f"  H1 -> Server            : {h1_to_s / mb:.4f}")
    print(f"  H2 -> Server            : {h2_to_s / mb:.4f}")
    print(f"  Server -> Holders       : {s_to_h / mb:.4f}")
    if have_hh:
        print(f"  Holder <-> Holder       : {hh_total / mb:.4f}")
    print(f"  TOTAL                   : {total_comm / mb:.4f}")

    print("\nMonetary cost (US cents):")
    print(f"  Egress                  : {egress_cost_usd * 100:.4f}")
    if have_timings:
        print(f"  Compute ({cpu_seconds:.1f} CPU-s) : "
              f"{compute_cost_usd * 100:.4f}")
    print(f"  TOTAL                   : {total_cost_usd * 100:.4f}")
    print()


if __name__ == "__main__":
    main()