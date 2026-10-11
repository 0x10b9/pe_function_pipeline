"""Emit samples/ground_truth.json for the test fixture from its export table.

Only the *evaluation* uses this file (to attach names / designed intent to
addresses). The pipeline itself never reads symbol names or this file.
"""
import json
import sys
from pathlib import Path

import pefile

EXPECTED = {
    "compute_checksum": "benign",
    "log_message": "benign",
    "persist_run_key": "suspicious",
    "fetch_remote_file": "suspicious",
    "run_shell_command": "suspicious",
}

exe = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("test_fixture.exe"))
pe = pefile.PE(str(exe))
base = pe.OPTIONAL_HEADER.ImageBase
gt = {}
for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    name = s.name.decode()
    gt[hex(base + s.address)] = dict(name=name, expected=EXPECTED.get(name, "unknown"))
out = exe.with_name("ground_truth.json")
out.write_text(json.dumps(gt, indent=1))
print(out, len(gt), "functions")
