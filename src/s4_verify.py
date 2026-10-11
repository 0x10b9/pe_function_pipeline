"""Step 4 - verify what the model pointed at.

Layer 1 (implemented): rule check on API + recovered arguments.
Layer 2 (not implemented here): capa / FLOSS / VirusTotal behaviour reports.
Layer 3 (not implemented here): manual review in Ghidra, or runtime hooks.

Verdict per function:
  suspicious    at least one confirmed behaviour (argument matched a rule) or an
                intrinsically high-risk API (e.g. CreateRemoteThread)
  needs_review  a sensitive API whose checked arguments could not be recovered,
                or a medium-risk API without arg checks
  weak          only low-risk, very common APIs (informational)
  no_evidence   nothing matched
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rules import LEVELS, rules_for_api  # noqa: E402


def _args_by_name(call):
    return {a["name"]: a for a in call["args"]}


def check_call(call) -> list[dict]:
    ev = []
    byname = _args_by_name(call)
    for rule in rules_for_api(call["api"]):
        if rule.checks:
            matched, unresolved = [], False
            for chk in rule.checks:
                names = chk.arg.split("|")
                cands = [byname[n] for n in names if n in byname]
                for a in cands:
                    if a["kind"] == "unknown":
                        unresolved = True
                    elif re.search(chk.pattern, a["text"]):
                        matched.append((chk, a))
            if matched:
                for chk, a in matched:
                    ev.append(dict(rule=rule.id, category=rule.category, level="suspicious",
                                   api=call["api"], call_addr=hex(call["call_addr"]),
                                   reason=chk.reason, arg=a["name"], value=a["text"]))
            elif unresolved:
                ev.append(dict(rule=rule.id, category=rule.category, level="needs_review",
                               api=call["api"], call_addr=hex(call["call_addr"]),
                               reason="sensitive API, checked argument not recoverable statically",
                               arg=None, value=None))
        else:
            level = {"high": "suspicious", "medium": "needs_review", "low": "weak"}[rule.severity]
            ev.append(dict(rule=rule.id, category=rule.category, level=level, api=call["api"],
                           call_addr=hex(call["call_addr"]),
                           reason=rule.note or "API-only match (no argument check)", arg=None, value=None))
        # apply per-rule cap
        for e in ev:
            if e["rule"] == rule.id and LEVELS[e["level"]] > LEVELS[rule.cap]:
                e["level"] = rule.cap
    return ev


def run(out_dir: Path) -> dict:
    calls = json.loads((out_dir / "03_api_calls.json").read_text())
    res = {}
    for fa, cs in calls.items():
        evidence = [e for c in cs for e in check_call(c)]
        verdict = max((e["level"] for e in evidence), key=lambda l: LEVELS[l], default="no_evidence")
        res[fa] = dict(verdict=verdict, categories=sorted({e["category"] for e in evidence
                                                          if e["level"] in ("suspicious", "needs_review")}),
                       n_import_calls=len(cs), evidence=evidence)
    (out_dir / "04_verdicts.json").write_text(json.dumps(res, indent=1))
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    r = run(Path(a.out))
    from collections import Counter
    print(Counter(v["verdict"] for v in r.values()))
