#!/usr/bin/env python3
"""prefetch_hash.py - compute the hash in a Prefetch file name (EXE-XXXXXXXX.pf) from the program's path.

Usage: prefetch_hash.py '\\DEVICE\\HARDDISKVOLUME3\\WINDOWS\\SYSTEM32\\CMD.EXE' [more paths...]

Windows Vista and later (Prefetch versions 23, 26, 30) hash the program's full device path, so the
same program run from two folders (or two volumes) gets two different .pf files. Hosting processes
(svchost.exe, dllhost.exe, rundll32.exe, mmc.exe, ...) also mix their command line into the hash,
which this script does not do. Standard library only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mk_execution_artifacts import scca_hash  # noqa: E402

if len(sys.argv) < 2:
    sys.exit(__doc__)
for path in sys.argv[1:]:
    exe = path.replace("/", "\\").split("\\")[-1].upper()
    print(f"{exe}-{scca_hash(path):08X}.pf  <-  {path.upper()}")
