"""Step 2 - function importance from a graph model + explanation.

IMPORTANT: no trained model exists in this project yet. `RandomGCNScorer` is a
*stand-in* with randomly initialised weights, so its function ranking is NOT
evidence about malware. It exists to exercise the plumbing (graph in ->
file-level logit -> per-function importance by occlusion -> top-k) so that a
trained model can be dropped in behind the same interface.

To plug in a trained GNN (e.g. PyTorch Geometric): subclass `Scorer`, implement
`logit(X, A)` returning the file-level malicious logit for a (sub)graph, and
pass it to `explain_by_occlusion`. GNNExplainer/attention can replace
occlusion; the output format (addr -> importance) stays the same.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import scipy.sparse as sp


class Scorer:
    def logit(self, X: np.ndarray, A: sp.csr_matrix) -> float:
        raise NotImplementedError


class RandomGCNScorer(Scorer):
    """3-layer GCN + mean pooling with random weights (stand-in, untrained)."""

    name = "random_init_gcn_standin"

    def __init__(self, in_dim: int, hidden: int = 16, layers: int = 3, seed: int = 0):
        rng = np.random.default_rng(seed)
        dims = [in_dim] + [hidden] * layers
        self.W = [rng.normal(0, 1 / np.sqrt(dims[i]), (dims[i], dims[i + 1])).astype(np.float32)
                  for i in range(layers)]
        self.w_out = rng.normal(0, 1 / np.sqrt(hidden), hidden).astype(np.float32)
        self.b = 0.0

    @staticmethod
    def _norm(A: sp.csr_matrix) -> sp.csr_matrix:
        A = A + sp.eye(A.shape[0], dtype=np.float32, format="csr")
        d = np.asarray(A.sum(1)).ravel()
        dinv = sp.diags(1.0 / np.sqrt(d))
        return dinv @ A @ dinv

    def logit(self, X, A) -> float:
        if X.shape[0] == 0:
            return 0.0
        An = self._norm(A)
        H = X
        for W in self.W:
            H = np.maximum(An @ (H @ W), 0)
        return float(H.mean(0) @ self.w_out + self.b)


def load_graph(npz_path: Path):
    z = np.load(npz_path)
    n = z["X"].shape[0]
    A = sp.coo_matrix((np.ones(len(z["src"]), dtype=np.float32), (z["src"], z["dst"])),
                      shape=(n, n)).tocsr()
    A = ((A + A.T) > 0).astype(np.float32).tocsr()
    return z["X"], A, z["node_func"], z["node_addr"]


def explain_by_occlusion(scorer: Scorer, X, A, node_func):
    """importance(f) = logit(full graph) - logit(graph without f's blocks)."""
    base = scorer.logit(X, A)
    imp = {}
    for f in np.unique(node_func):
        keep = node_func != f
        idx = np.flatnonzero(keep)
        imp[int(f)] = base - scorer.logit(X[idx], A[idx][:, idx])
    return base, imp


def run(out_dir: Path, k: int = 5, seed: int = 0) -> dict:
    X, A, node_func, _ = load_graph(out_dir / "01_graph.npz")
    scorer = RandomGCNScorer(X.shape[1], seed=seed)
    base, imp = explain_by_occlusion(scorer, X, A, node_func)
    ranked = sorted(imp.items(), key=lambda kv: -kv[1])
    res = dict(scorer=scorer.name, trained=False, seed=seed, file_logit=base,
               file_prob_malicious=float(1 / (1 + np.exp(-base))), k=k,
               ranking=[dict(rank=i + 1, addr=a, hex=hex(a), importance=v)
                        for i, (a, v) in enumerate(ranked)])
    res["topk"] = [r["addr"] for r in res["ranking"][:k]]
    (out_dir / "02_scores.json").write_text(json.dumps(res, indent=1))
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--k", type=int, default=5)
    a = ap.parse_args()
    r = run(Path(a.out), a.k)
    print(r["scorer"], "top-k:", [hex(x) for x in r["topk"]])
