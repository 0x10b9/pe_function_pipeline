"""Step 1 - packing check and CFG recovery.

Outputs (in <out_dir>):
  01_pack_check.json   section entropy + packer heuristics
  01_graph.npz         X (node features), src/dst (edges), node_func, node_addr
  01_functions.json    one record per recovered function
  01_instructions.json simplified disassembly per function/block (used by step 3)

The pipeline never uses symbol names: functions are identified by address,
exactly as they would be in a stripped malware sample.
"""
from __future__ import annotations

import argparse
import json
import logging
import math
from pathlib import Path

import numpy as np
import pefile

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)
logging.getLogger("pyvex").setLevel(logging.CRITICAL)

PACKER_SECTIONS = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1",
                   ".petite", ".nsp0", ".nsp1", ".MPRESS1", ".MPRESS2", ".enigma1"}

# ----------------------------------------------------------------- packing check

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def pack_check(path: str) -> dict:
    pe = pefile.PE(path)
    sections, reasons = [], []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        ch = s.Characteristics
        rec = dict(name=name, entropy=round(shannon_entropy(s.get_data()), 3),
                   raw_size=s.SizeOfRawData, virtual_size=s.Misc_VirtualSize,
                   executable=bool(ch & 0x20000000), writable=bool(ch & 0x80000000))
        sections.append(rec)
        if name in PACKER_SECTIONS:
            reasons.append(f"packer-style section name {name}")
        if rec["executable"] and rec["entropy"] >= 7.0:
            reasons.append(f"executable section {name} has high entropy ({rec['entropy']})")
        if rec["executable"] and rec["writable"]:
            reasons.append(f"section {name} is writable and executable")
        if rec["executable"] and rec["raw_size"] == 0 and rec["virtual_size"] > 0:
            reasons.append(f"executable section {name} is empty on disk (filled at runtime)")
    n_imports = sum(len(e.imports) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
    if n_imports <= 5:
        reasons.append(f"very few imports ({n_imports}); API names may be resolved at runtime")
    return dict(sections=sections, n_imports=n_imports,
                likely_packed=bool(reasons), reasons=reasons)

# ----------------------------------------------------------------- features

CATEGORIES = ["mov", "lea", "arith", "logic", "shift", "stack", "cmp", "jmp", "jcc", "call",
              "ret", "other"]
_CAT = {}
for m in "mov movzx movsx movsxd movabs cmovz cmovnz cmove cmovne cmova cmovb cmovg cmovl xchg cdqe cqo cdq".split():
    _CAT[m] = "mov"
_CAT["lea"] = "lea"
for m in "add sub inc dec neg imul mul idiv div adc sbb".split():
    _CAT[m] = "arith"
for m in "and or xor not".split():
    _CAT[m] = "logic"
for m in "shl shr sar sal rol ror".split():
    _CAT[m] = "shift"
for m in "push pop leave".split():
    _CAT[m] = "stack"
for m in "cmp test".split():
    _CAT[m] = "cmp"
_CAT["jmp"] = "jmp"
_CAT["call"] = "call"
_CAT["ret"] = "ret"
_CAT["retn"] = "ret"
for m in "je jne jz jnz ja jae jb jbe jg jge jl jle js jns jo jno jp jnp jcxz jecxz jrcxz".split():
    _CAT[m] = "jcc"


def _cat_index(mnemonic: str) -> int:
    return CATEGORIES.index(_CAT.get(mnemonic, "other"))


N_FEATURES = len(CATEGORIES) + 2   # + log(#insns) + imports-called flag


def _dump_operands(ci):
    from capstone import x86 as cx
    ops = []
    for op in ci.operands:
        if op.type == cx.X86_OP_REG:
            ops.append({"t": "reg", "n": ci.reg_name(op.reg)})
        elif op.type == cx.X86_OP_IMM:
            ops.append({"t": "imm", "v": int(op.imm)})
        elif op.type == cx.X86_OP_MEM:
            m = op.mem
            ops.append({"t": "mem", "base": ci.reg_name(m.base) if m.base else None,
                        "index": ci.reg_name(m.index) if m.index else None,
                        "scale": int(m.scale), "disp": int(m.disp), "size": int(op.size)})
        else:
            ops.append({"t": "other"})
    return ops

# ----------------------------------------------------------------- CFG

def extract_cfg(path: str, out_dir: Path) -> dict:
    import angr

    proj = angr.Project(path, auto_load_libs=False)
    obj = proj.loader.main_object
    exec_ranges = [(s.vaddr, s.vaddr + s.memsize) for s in obj.sections if s.is_executable]

    def in_exec(a):
        return any(lo <= a < hi for lo, hi in exec_ranges)

    cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)

    functions, instructions = [], {}
    feats, node_func, node_addr = [], [], []
    node_index = {}                       # block addr -> node idx
    func_edges, func_callsites = [], []   # filled after all nodes exist

    kept = []
    for f in cfg.kb.functions.values():
        if f.is_simprocedure or f.is_plt or f.is_syscall or f.is_alignment:
            continue
        if not in_exec(f.addr):
            continue
        kept.append(f)
    kept.sort(key=lambda f: f.addr)

    for f in kept:
        blocks = sorted(f.blocks, key=lambda b: b.addr)
        if not blocks:
            continue
        func_blocks, n_insns = [], 0
        for b in blocks:
            insns = list(b.capstone.insns)
            n_insns += len(insns)
            recs = []
            vec = np.zeros(N_FEATURES, dtype=np.float32)
            imp_call = 0.0
            for i in insns:
                ci = i.insn
                ops = _dump_operands(ci)
                recs.append(dict(a=int(ci.address), s=int(ci.size), m=ci.mnemonic, ops=ops))
                vec[_cat_index(ci.mnemonic)] += 1
                if ci.mnemonic == "call" and ops and ops[0]["t"] == "mem" and ops[0]["base"] == "rip":
                    imp_call = 1.0
            n = max(len(insns), 1)
            vec[:len(CATEGORIES)] /= n
            vec[len(CATEGORIES)] = math.log1p(len(insns)) / 5.0
            vec[len(CATEGORIES) + 1] = imp_call
            node_index[b.addr] = len(feats)
            feats.append(vec)
            node_func.append(f.addr)
            node_addr.append(b.addr)
            func_blocks.append(dict(block=int(b.addr), insns=recs))
        instructions[hex(f.addr)] = func_blocks
        functions.append(dict(addr=int(f.addr), hex=hex(f.addr), size=int(f.size),
                              n_blocks=len(blocks), n_insns=n_insns))

    fset = {fn["addr"] for fn in functions}
    src, dst = [], []
    for f in kept:
        if f.addr not in fset:
            continue
        for u, v in f.graph.edges():
            ua, va = getattr(u, "addr", None), getattr(v, "addr", None)
            if ua in node_index and va in node_index:
                src.append(node_index[ua]); dst.append(node_index[va])
        for site in f.get_call_sites():
            tgt = f.get_call_target(site)
            if tgt in fset and tgt in node_index and site in node_index:
                src.append(node_index[site]); dst.append(node_index[tgt])

    out_dir.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(out_dir / "01_graph.npz", X=np.vstack(feats),
                        src=np.array(src, dtype=np.int64), dst=np.array(dst, dtype=np.int64),
                        node_func=np.array(node_func, dtype=np.int64),
                        node_addr=np.array(node_addr, dtype=np.int64))
    (out_dir / "01_functions.json").write_text(json.dumps(functions, indent=1))
    (out_dir / "01_instructions.json").write_text(json.dumps(instructions))
    return dict(n_functions=len(functions), n_blocks=len(feats), n_edges=len(src))


def run(path: str, out_dir: Path, force: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    pc = pack_check(path)
    (out_dir / "01_pack_check.json").write_text(json.dumps(pc, indent=1))
    if pc["likely_packed"] and not force:
        raise SystemExit("Sample looks packed; CFG would describe the unpacker stub. "
                         "Unpack it first or re-run with --force. Reasons: " + "; ".join(pc["reasons"]))
    stats = extract_cfg(path, out_dir)
    stats["pack_check"] = pc
    return stats


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("pe")
    ap.add_argument("--out", required=True)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    print(run(a.pe, Path(a.out), a.force))
