"""Step 3 - API calls and arguments for each function (x64 PE).

What it does, per function:
  * finds call sites that go through the import table (call [rip+IAT], call reg
    loaded from the IAT, or a one-instruction `jmp [IAT]` thunk);
  * recovers argument values with a tiny linear-sweep value tracker
    (constants, addresses of strings, stack slots) and renders strings from
    the PE image.

Known limits (be upfront about them in the thesis/report):
  * registers are reset at every basic block start; stack slots persist across
    blocks of a function, so a local assigned once and used later is recovered;
  * no real data-flow / taint analysis: values built by arithmetic across
    blocks, decrypted at runtime, or passed through reflection-like dynamic
    resolution come out as <unknown>;
  * x64 calling convention only (rcx, rdx, r8, r9, then [rsp+0x20...]).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rules import PROTOTYPES, normalize_api  # noqa: E402

# ---- register aliasing ------------------------------------------------------
ALIAS: dict[str, tuple[str, int]] = {}
for r in ("rax", "rbx", "rcx", "rdx"):
    b = r[1]
    ALIAS.update({r: (r, 64), f"e{b}x": (r, 32), f"{b}x": (r, 16), f"{b}l": (r, 8), f"{b}h": (r, 8)})
for r in ("rsi", "rdi", "rbp", "rsp"):
    ALIAS.update({r: (r, 64), "e" + r[1:]: (r, 32), r[1:]: (r, 16), r[1:] + "l": (r, 8)})
for i in range(8, 16):
    ALIAS.update({f"r{i}": (f"r{i}", 64), f"r{i}d": (f"r{i}", 32), f"r{i}w": (f"r{i}", 16),
                  f"r{i}b": (f"r{i}", 8)})
ARG_REGS = ["rcx", "rdx", "r8", "r9"]
VOLATILE = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]
M64 = 0xFFFFFFFFFFFFFFFF
HKEYS = {0x80000000: "HKEY_CLASSES_ROOT", 0x80000001: "HKEY_CURRENT_USER",
         0x80000002: "HKEY_LOCAL_MACHINE", 0x80000003: "HKEY_USERS"}


class PEView:
    def __init__(self, path: str):
        self.pe = pefile.PE(path)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.iat: dict[int, tuple[str, str]] = {}
        for e in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = e.dll.decode(errors="replace").lower()
            for imp in e.imports:
                name = imp.name.decode(errors="replace") if imp.name else f"ord{imp.ordinal}"
                self.iat[imp.address] = (dll, name)

    def in_image(self, va: int) -> bool:
        return self.base <= va < self.base + self.size

    def read(self, va: int, n: int) -> bytes | None:
        if not self.in_image(va):
            return None
        try:
            return self.pe.get_data(va - self.base, n)
        except Exception:
            return None

    def read_cstr(self, va: int) -> str | None:
        data = self.read(va, 260)
        if not data:
            return None
        # ASCII
        end = data.find(b"\x00")
        if end >= 3 and all(32 <= c < 127 or c in (9, 10, 13) for c in data[:end]):
            return data[:end].decode("ascii")
        # UTF-16LE
        if len(data) >= 8 and data[1] == 0 and data[3] == 0:
            chars = []
            for i in range(0, len(data) - 1, 2):
                c = data[i] | (data[i + 1] << 8)
                if c == 0:
                    break
                chars.append(c)
            if len(chars) >= 3 and all(32 <= c < 127 for c in chars):
                return "".join(map(chr, chars))
        return None

    def thunk_target(self, va: int) -> tuple[str, str] | None:
        """`jmp qword ptr [rip+disp]` stub -> import."""
        b = self.read(va, 6)
        if b and b[0] == 0xFF and b[1] == 0x25:
            disp = int.from_bytes(b[2:6], "little", signed=True)
            return self.iat.get(va + 6 + disp)
        return None


def _canon(reg: str):
    return ALIAS.get(reg)


class Tracker:
    """Linear-sweep constant/pointer tracker for one function."""

    def __init__(self, pev: PEView):
        self.pev = pev
        self.mem: dict[tuple[str, int], object] = {}
        self.regs: dict[str, object] = {}

    # values: None | int | ("stack", base, disp) | ("imp", dll, name)
    def _read_op(self, op, insn_end):
        t = op["t"]
        if t == "imm":
            return op["v"] & M64
        if t == "reg":
            c = _canon(op["n"])
            if not c:
                return None
            v = self.regs.get(c[0])
            if v is None or c[1] == 64:
                return v
            return v & 0xFFFFFFFF if (c[1] == 32 and isinstance(v, int)) else None
        if t == "mem":
            if op["base"] == "rip" and not op["index"]:
                va = insn_end + op["disp"]
                if va in self.pev.iat:
                    return ("imp",) + self.pev.iat[va]
                data = self.pev.read(va, 8)
                if data and len(data) == 8 and op["size"] == 8:
                    return int.from_bytes(data, "little")
                return None
            if op["base"] in ("rsp", "rbp") and not op["index"]:
                return self.mem.get((op["base"], op["disp"]))
        return None

    def _write_reg(self, name, value):
        c = _canon(name)
        if not c:
            return
        reg, width = c
        if width == 64:
            self.regs[reg] = value
        elif width == 32:
            self.regs[reg] = (value & 0xFFFFFFFF) if isinstance(value, int) else None
        else:
            self.regs[reg] = None

    def start_block(self):
        self.regs = {}

    def step(self, ins):
        m, ops = ins["m"], ins["ops"]
        end = ins["a"] + ins["s"]
        if m in ("mov", "movabs") and len(ops) == 2:
            v = self._read_op(ops[1], end)
            if ops[0]["t"] == "reg":
                self._write_reg(ops[0]["n"], v)
            elif ops[0]["t"] == "mem" and ops[0]["base"] in ("rsp", "rbp") and not ops[0]["index"]:
                self.mem[(ops[0]["base"], ops[0]["disp"])] = v
        elif m == "lea" and len(ops) == 2 and ops[0]["t"] == "reg" and ops[1]["t"] == "mem":
            mo = ops[1]
            if mo["base"] == "rip" and not mo["index"]:
                self._write_reg(ops[0]["n"], (end + mo["disp"]) & M64)
            elif mo["base"] in ("rsp", "rbp") and not mo["index"]:
                self._write_reg(ops[0]["n"], ("stack", mo["base"], mo["disp"]))
            else:
                self._write_reg(ops[0]["n"], None)
        elif m == "xor" and len(ops) == 2 and ops[0] == ops[1] and ops[0]["t"] == "reg":
            self._write_reg(ops[0]["n"], 0)
        elif m in ("cmp", "test", "push", "nop", "jmp", "ret", "leave", "call") or m.startswith("j"):
            pass
        elif m in ("add", "sub") and len(ops) == 2 and ops[0]["t"] == "reg" and ops[1]["t"] == "imm":
            c = _canon(ops[0]["n"])
            cur = self.regs.get(c[0]) if c else None
            if isinstance(cur, int) and c[1] == 64:
                d = ops[1]["v"]
                self._write_reg(ops[0]["n"], (cur + d if m == "add" else cur - d) & M64)
            else:
                self._write_reg(ops[0]["n"], None)
        elif ops and ops[0]["t"] == "reg":
            self._write_reg(ops[0]["n"], None)       # unknown write
        elif ops and ops[0]["t"] == "mem" and ops[0]["base"] in ("rsp", "rbp") and not ops[0]["index"]:
            self.mem[(ops[0]["base"], ops[0]["disp"])] = None

    def clobber_call(self):
        for r in VOLATILE:
            self.regs[r] = None

    def arg_value(self, i: int):
        if i < 4:
            return self.regs.get(ARG_REGS[i])
        return self.mem.get(("rsp", 0x20 + 8 * (i - 4)))


def render(pev: PEView, v) -> dict:
    if v is None:
        return {"kind": "unknown", "text": "<unknown>"}
    if isinstance(v, tuple):
        if v[0] == "stack":
            return {"kind": "stack_addr", "text": f"&local({v[1]}{v[2]:+#x})"}
        return {"kind": "import", "text": f"{v[2]}"}
    if isinstance(v, int):
        low = v & 0xFFFFFFFF
        if (v >> 32) in (0, 0xFFFFFFFF) and low in HKEYS:
            return {"kind": "const", "value": low, "text": HKEYS[low]}
        if pev.in_image(v):
            s = pev.read_cstr(v)
            if s is not None:
                return {"kind": "string", "value": v, "text": s}
            return {"kind": "pointer", "value": v, "text": hex(v)}
        sv = v - (1 << 64) if v >> 63 else v
        return {"kind": "const", "value": v, "text": hex(v) if abs(sv) > 9 else str(sv)}
    return {"kind": "unknown", "text": "<unknown>"}


def analyse_function(pev: PEView, blocks: list[dict]) -> list[dict]:
    tr = Tracker(pev)
    calls = []
    for blk in blocks:
        tr.start_block()
        for ins in blk["insns"]:
            if ins["m"] == "call" and ins["ops"]:
                op = ins["ops"][0]
                end = ins["a"] + ins["s"]
                target = None
                if op["t"] == "mem" and op["base"] == "rip" and not op["index"]:
                    target = pev.iat.get(end + op["disp"])
                elif op["t"] == "reg":
                    v = tr._read_op(op, end)
                    if isinstance(v, tuple) and v[0] == "imp":
                        target = (v[1], v[2])
                elif op["t"] == "imm":
                    target = pev.thunk_target(op["v"] & M64)
                if target:
                    dll, name = target
                    api = normalize_api(name)
                    names = PROTOTYPES.get(api)
                    args = []
                    if names:
                        for i, an in enumerate(names):
                            args.append({"name": an, **render(pev, tr.arg_value(i))})
                    else:
                        for i in range(4):
                            v = tr.arg_value(i)
                            if v is not None:
                                args.append({"name": f"arg{i}", **render(pev, v)})
                    calls.append(dict(call_addr=ins["a"], dll=dll, api_raw=name, api=api, args=args))
                tr.clobber_call()
            else:
                tr.step(ins)
    return calls


def run(pe_path: str, out_dir: Path) -> dict:
    pev = PEView(pe_path)
    instructions = json.loads((out_dir / "01_instructions.json").read_text())
    result = {fa: analyse_function(pev, blocks) for fa, blocks in instructions.items()}
    (out_dir / "03_api_calls.json").write_text(json.dumps(result, indent=1))
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("pe")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    r = run(a.pe, Path(a.out))
    print(len(r), "functions;", sum(len(v) for v in r.values()), "import calls")
