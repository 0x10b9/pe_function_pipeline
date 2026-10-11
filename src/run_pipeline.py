"""Run the 5-step pipeline on one PE file and print the result for one function.

    python src/run_pipeline.py samples/test_fixture.exe --k 5 --focus 0x1400011d0
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import s1_extract, s2_score, s3_apis, s4_verify, s5_metrics  # noqa: E402


def focus_report(out_dir: Path, focus: int, gt: dict) -> str:
    h = hex(focus)
    scores = json.loads((out_dir / "02_scores.json").read_text())
    calls = json.loads((out_dir / "03_api_calls.json").read_text()).get(h)
    ver = json.loads((out_dir / "04_verdicts.json").read_text()).get(h)
    funcs = {f["addr"]: f for f in json.loads((out_dir / "01_functions.json").read_text())}
    if calls is None or focus not in funcs:
        return f"Function {h} was not recovered by the CFG step."
    rank = next(r for r in scores["ranking"] if r["addr"] == focus)
    g = gt.get(h)
    f = funcs[focus]
    L = [f"## Function {h}"]
    if g:
        L.append(f"- Fixture ground truth (evaluation only): `{g['name']}`, designed as **{g['expected']}**")
    L.append(f"- CFG: {f['n_blocks']} basic blocks, {f['n_insns']} instructions, {f['size']} bytes")
    L.append(f"- Step 2 ({scores['scorer']}, trained={scores['trained']}): rank "
             f"{rank['rank']} / {len(scores['ranking'])}, importance {rank['importance']:+.6f}, "
             f"{'IN' if focus in scores['topk'] else 'NOT in'} top-{scores['k']}")
    L.append("- Step 3 - import calls and recovered arguments:")
    for c in calls:
        args = ", ".join(f"{a['name']}={a['text']!r}" for a in c["args"]) or "(no args recovered)"
        L.append(f"  - `{c['api_raw']}` @ {hex(c['call_addr'])} ({c['dll']}): {args}")
    L.append(f"- Step 4 - verdict: **{ver['verdict']}**  (categories: {', '.join(ver['categories']) or '-'})")
    for e in ver["evidence"]:
        if e["level"] in ("suspicious", "needs_review"):
            L.append(f"  - [{e['level']}] {e['rule']} via `{e['api']}` @ {e['call_addr']}: {e['reason']}"
                     + (f" ({e['arg']} = {e['value']!r})" if e["arg"] else ""))
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pe")
    ap.add_argument("--out", default=None, help="default: outputs/<file stem>")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--focus", default=None, help="function address to report, e.g. 0x1400011d0")
    ap.add_argument("--gt", default=None, help="ground_truth.json (fixture evaluation only)")
    ap.add_argument("--force", action="store_true", help="continue even if the sample looks packed")
    a = ap.parse_args()

    pe = Path(a.pe)
    root = Path(__file__).resolve().parents[1]
    out = Path(a.out) if a.out else root / "outputs" / pe.stem
    gt_path = Path(a.gt) if a.gt else pe.with_name("ground_truth.json")

    t = time.time()
    print("[1/5] packing check + CFG ...", flush=True)
    s1 = s1_extract.run(str(pe), out, a.force)
    print(f"      {s1['n_functions']} functions, {s1['n_blocks']} blocks, {s1['n_edges']} edges "
          f"(packed={s1['pack_check']['likely_packed']})", flush=True)
    print("[2/5] scoring + occlusion ...", flush=True)
    s2 = s2_score.run(out, a.k)
    print("      top-k:", [hex(x) for x in s2["topk"]], flush=True)
    print("[3/5] API calls + arguments ...", flush=True)
    s3 = s3_apis.run(str(pe), out)
    print("[4/5] rule verification ...", flush=True)
    s4 = s4_verify.run(out)
    print("[5/5] metrics ...", flush=True)
    s5 = s5_metrics.run(out, gt_path, a.k)
    print(f"done in {time.time() - t:.0f}s -> {out}\n")

    gt = json.loads(gt_path.read_text()) if gt_path.exists() else {}
    parts = []
    if a.focus:
        parts.append(focus_report(out, int(a.focus, 16), gt))
    m = s5
    parts.append(
        "## Metrics (k=%d)\n"
        "- precision@k of model top-k vs verifier `suspicious`: %.2f (hits %d of %d positives)\n"
        "- baseline random-k precision: %.4f; largest-k precision: %.2f\n"
        "- fidelity: logit drop %.6f when top-k removed vs %.6f for random-k (std %.6f)\n"
        % (a.k, m["precision_recall_at_k"]["precision"], m["precision_recall_at_k"]["hits"],
           m["precision_recall_at_k"]["n_positives"], m["baselines"]["random_k_mean_precision"],
           m["baselines"]["largest_k"]["precision"], m["fidelity"]["logit_drop_topk"],
           m["fidelity"]["logit_drop_random_k_mean"], m["fidelity"]["logit_drop_random_k_std"]))
    if "verifier_sanity" in m:
        v = m["verifier_sanity"]
        parts.append(f"- verifier sanity on fixture: {v['correct']}/{v['total']} correct; "
                     f"`suspicious` outside fixture: {len(v['suspicious_outside_fixture'])}")
    report = "\n\n".join(parts)
    (out / "report.md").write_text(report)
    print(report)


if __name__ == "__main__":
    main()
