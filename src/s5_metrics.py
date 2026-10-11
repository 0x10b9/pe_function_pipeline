"""Step 5 - metrics.

Three things are measured, and they answer different questions:

A. Verifier sanity (fixture only): does step 4 flag exactly the functions that
   were written to be suspicious? Needs samples/ground_truth.json.
B. Precision@k / recall@k of the model's top-k functions, using the verifier's
   `suspicious` verdict as the reference label, against two baselines
   (random-k, largest-k functions). The reference label is rule-derived, so this
   measures agreement with the rules, not ground truth about the malware.
C. Fidelity: how much the file-level logit drops when the top-k functions are
   removed from the graph, versus removing k random functions.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s2_score import RandomGCNScorer, load_graph  # noqa: E402


def precision_recall_at_k(topk, positives, all_funcs):
    hit = len(set(topk) & positives)
    return dict(precision=hit / len(topk) if topk else 0.0,
                recall=hit / len(positives) if positives else None, hits=hit,
                n_positives=len(positives), n_functions=len(all_funcs))


def run(out_dir: Path, gt_path: Path | None = None, k: int = 5, n_random: int = 2000, seed: int = 0) -> dict:
    scores = json.loads((out_dir / "02_scores.json").read_text())
    verdicts = json.loads((out_dir / "04_verdicts.json").read_text())
    funcs = json.loads((out_dir / "01_functions.json").read_text())
    rng = np.random.default_rng(seed)

    all_f = [f["addr"] for f in funcs]
    size = {f["addr"]: f["n_insns"] for f in funcs}
    pos = {int(a, 16) for a, v in verdicts.items() if v["verdict"] == "suspicious"}
    pos_or_review = {int(a, 16) for a, v in verdicts.items() if v["verdict"] in ("suspicious", "needs_review")}
    topk = scores["topk"][:k]

    # B. precision@k vs baselines
    model = precision_recall_at_k(topk, pos, all_f)
    model_incl_review = precision_recall_at_k(topk, pos_or_review, all_f)
    rand_p = []
    for _ in range(n_random):
        pick = rng.choice(all_f, size=k, replace=False)
        rand_p.append(len(set(pick.tolist()) & pos) / k)
    largest = sorted(all_f, key=lambda a: -size[a])[:k]
    baselines = dict(random_k_mean_precision=float(np.mean(rand_p)),
                     largest_k=precision_recall_at_k(largest, pos, all_f))

    # C. fidelity by occlusion
    X, A, node_func, _ = load_graph(out_dir / "01_graph.npz")
    sc = RandomGCNScorer(X.shape[1], seed=scores["seed"])
    base = sc.logit(X, A)

    def drop(remove):
        keep = np.flatnonzero(~np.isin(node_func, list(remove)))
        return base - sc.logit(X[keep], A[keep][:, keep])

    fid_model = float(drop(topk))
    fid_rand = [float(drop(rng.choice(all_f, size=k, replace=False).tolist())) for _ in range(200)]
    fidelity = dict(logit_drop_topk=fid_model, logit_drop_random_k_mean=float(np.mean(fid_rand)),
                    logit_drop_random_k_std=float(np.std(fid_rand)),
                    file_logit=base, file_prob=float(1 / (1 + np.exp(-base))))

    res = dict(k=k, topk=[hex(a) for a in topk], model_is_trained=scores["trained"],
               precision_recall_at_k=model, precision_recall_at_k_incl_needs_review=model_incl_review,
               baselines=baselines, fidelity=fidelity)

    # A. verifier sanity
    if gt_path and gt_path.exists():
        gt = json.loads(gt_path.read_text())
        rows, correct = [], 0
        for a, g in gt.items():
            got = verdicts.get(a, {}).get("verdict", "missing")
            ok = (g["expected"] == "suspicious") == (got == "suspicious")
            correct += ok
            rows.append(dict(addr=a, name=g["name"], expected=g["expected"], verifier=got, ok=ok))
        flagged_other = [a for a, v in verdicts.items() if v["verdict"] == "suspicious" and a not in gt]
        res["verifier_sanity"] = dict(rows=rows, correct=correct, total=len(rows),
                                      suspicious_outside_fixture=flagged_other)
    (out_dir / "05_metrics.json").write_text(json.dumps(res, indent=1))
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--gt")
    ap.add_argument("--k", type=int, default=5)
    a = ap.parse_args()
    r = run(Path(a.out), Path(a.gt) if a.gt else None, a.k)
    print(json.dumps({k: v for k, v in r.items() if k != "verifier_sanity"}, indent=1))
    print(json.dumps(r.get("verifier_sanity"), indent=1))
