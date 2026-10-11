#!/usr/bin/env bash
# Rebuild the benign PE test fixture and its ground-truth file (cross-compiled with zig cc).
set -euo pipefail
cd "$(dirname "$0")"
python -m ziglang cc -target x86_64-windows-gnu -O0 -g0 -Wl,--gc-sections \
    test_fixture.c -o test_fixture.exe -lurlmon -ladvapi32 -lkernel32
rm -f test_fixture.pdb test_fixture.lib
python make_ground_truth.py test_fixture.exe
