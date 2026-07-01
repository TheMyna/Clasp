# config.py
# Every cost-model constant lives here, each with its provenance.
# To "play" with the study, edit values here. The model code reads only these.

# --- Structure: objects each record carries (CLASP as written) ---
CIPHERTEXTS_PER_H1_RECORD = 4    # Eq. (h1upload): sum, alpha*rho, count, alpha
CIPHERTEXTS_PER_H2_RECORD = 1    # Eq. (h2upload): one binding ciphertext
TAGS_PER_RECORD = 1
CIPHERTEXTS_RETURNED_PER_SEGMENT = 4   # (s_b, alpha*s_b, c_b, alpha*c_b)

# --- Element sizes in bytes ---
# A CL ciphertext at 128-bit security is 2 class-group elements over an
# ~1827-bit discriminant (Biasse-Jacobson-Silvester; BICYCL): ~229 B
# compressed to ~457 B uncompressed. MEASURE the exact value from BICYCL.
CL_CIPHERTEXT_BYTES = 457
TAG_BYTES = 32                   # 2*lambda-bit hashed DH-OPRF output

# Holder-to-holder channel sizes. PLACEHOLDERS, refine with the harness.
DOPRF_BYTES_PER_EVAL = 200       # DH-OPRF message + DLEQ proof (placeholder)
PARTDEC_BYTES_PER_CT = 500       # partial decryption + proof (placeholder)

# --- Sentinels (differential privacy floor) ---
ETA_MIN = 30                     # per-segment floor; modeled E = B * ETA_MIN

# --- Cloud prices (Ion et al., Table 1, GCP) ---
EGRESS_USD_PER_GB = 0.08
CPU_USD_PER_HOUR = 0.01

# --- Unit timings, seconds. None = NOT MEASURED; needs the BICYCL harness. ---
# Leave as None and the study skips absolute time (counts stay reliable).
SEC_PER_CL_ENC = 0.00457          # 4.57 ms, BICYCL CL-HSMqk 128-bit, none variant
SEC_PER_CL_ADD = 0.00000885       # 8.85 us, nucomp (class-group composition)
SEC_PER_THRESHOLD_DEC = 0.01061   # 10.61 ms, decrypt

SEC_PER_SCALAR_MULT = 0.0    # not benchmarked; excluded from total
SEC_PER_DOPRF_EVAL = 0.0     # different library; excluded from total

# --- Sweep ranges the study drives itself ---
SWEEP_SET_SIZES = [1000, 10000, 100000, 1000000, 10000000]
SWEEP_SEGMENTS_FIXED = 100        # B held fixed during the n-sweep
SWEEP_SEGMENT_COUNTS = [1, 10, 100, 1000, 10000]   # for the B sensitivity study
SWEEP_ETA_MIN_VALUES = [0, 10, 30, 100, 300]       # for the E crossover study
SWEEP_FIXED_N = 100000            # n held fixed during the B and eta sweeps