# CLASP

Analytical cost and scaling study for the CLASP delegated, segmented,
verifiable private intersection-sum-with-cardinality protocol.

## Files
- `config.py`        all cost constants and sweep ranges, with provenance
- `clasp_model.py`   pure cost model (no I/O, no hidden constants)
- `clasp_scaling.py` self-driving scaling study; finds the bottleneck
- `clasp_cost.py`    interactive single-point calculator

## Run
    python3 clasp_scaling.py     # parameter sweep + bottleneck + CSV
    python3 clasp_cost.py        # one configuration, interactive

Communication figures and operation counts are reliable now. Absolute
CPU-time is withheld until unit timings are measured from BICYCL and entered
in config.py. No costs are hardcoded.