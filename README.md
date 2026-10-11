# pe_func_pipeline

Function-level explanation and verification for CFG-based PE malware detection.
Given one Windows PE (x64), the pipeline recovers the CFG with angr, ranks
functions with a graph model, extracts the API calls and arguments inside each
function, and checks them against behaviour rules.

```
pe_func_pipeline/
├── README.md
├── requirements.txt
├── samples/
│   ├── test_fixture.c        benign fixture source (never meant to be run)
│   ├── test_fixture.exe      PE built from it (zig cc, x86_64-windows-gnu)
│   ├── ground_truth.json     address -> designed intent (evaluation only)
│   ├── make_ground_truth.py
│   └── build.sh
├── src/
│   ├── rules.py              API prototypes + behaviour rules
│   ├── s1_extract.py         step 1: packing check, angr CFG, node features
│   ├── s2_score.py           step 2: graph scorer + occlusion -> top-k functions
│   ├── s3_apis.py            step 3: API calls + argument recovery
│   ├── s4_verify.py          step 4: rule verification -> verdict per function
│   ├── s5_metrics.py         step 5: precision@k, baselines, fidelity
│   └── run_pipeline.py       runs 1..5 and prints a report for one function
└── outputs/<sample>/
    01_pack_check.json  01_graph.npz  01_functions.json  01_instructions.json
    02_scores.json  03_api_calls.json  04_verdicts.json  05_metrics.json  report.md
```

## Run

```bash
pip install -r requirements.txt
python src/run_pipeline.py samples/test_fixture.exe --k 5 --focus 0x1400011d0
# real sample (packed samples are refused unless --force):
python src/run_pipeline.py path/to/sample.exe --k 10 --focus 0x401000
```

## What is real and what is a stand-in

| Step | Status |
|---|---|
| 1 packing check + CFG (angr `CFGFast`) | real |
| 2 graph model | **stand-in**: untrained, randomly initialised 3-layer GCN. Its ranking carries no information about malware. Replace `RandomGCNScorer` with your trained GNN (same `logit(X, A)` interface) or swap occlusion for GNNExplainer/attention. |
| 3 API + argument recovery | real, but a linear-sweep tracker, not full data-flow/taint analysis |
| 4 verification | layer 1 only (API + argument rules). capa, FLOSS, VirusTotal behaviour reports and manual/dynamic review are not wired in. |
| 5 metrics | real; reference labels come from step 4, so precision@k measures agreement with the rules, not ground truth |

## Known limits

- Packed or heavily obfuscated samples: CFG describes the unpacker; arguments
  built at runtime or decrypted strings come out as `<unknown>`.
- `needs_review` means "sensitive API, arguments not recoverable" - route those
  to FLOSS / a sandbox / manual reading.
- x64 only; x86 stack-based argument passing is not implemented.
- The fixture is deliberately small and clean; a real sample will have many more
  `needs_review` functions and a noisier ranking.
