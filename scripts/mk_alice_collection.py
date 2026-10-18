#!/usr/bin/env python3
"""mk_alice_collection.py - put the WS-ALICE artifacts of Days 11 to 18 into one triage collection.

Usage: python3 mk_alice_collection.py OUTDIR

Runs the course's generators and arranges their output the way a triage collection (KAPE, Day 9)
lays out a Windows system, under OUTDIR/C/:

  Windows/System32/winevt/Logs/*.evtx            event logs and Sysmon (Days 14 to 16)
  Windows/System32/config/SYSTEM, SOFTWARE       registry (Day 11: the hives as of 2026-09-29 01:22)
  Windows/System32/config/RegBack/SYSTEM         ... and the SYSTEM hive saved after the 07:58 reboot
                                                 (Day 12: Shimcache and BAM). Two copies of one hive,
                                                 from different times, as a collection often holds
  Windows/Prefetch/*.pf                          Prefetch (Day 12)
  Windows/AppCompat/Programs/Amcache.hve         Amcache (Day 12)
  Users/alice/NTUSER.DAT                         alice's hive (Day 11)
  Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat, .../Recent/*.lnk, AutomaticDestinations
                                                 ShellBags, LNK files and Jump Lists (Day 13)
  Users/alice/AppData/{Local,Roaming}/...        Edge and Firefox profiles (Day 18)

The NTFS volume of Day 10 is a disk image; build it separately with mk_ntfs_case10.sh. Every file
is byte-identical on every run and keeps the modification time its generator set. Standard library
only (it runs the other generators from the same folder).
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# (generator, path in its output, path under OUTDIR/C)
MOVES = [
    ("mk_event_logs", "Windows/System32/winevt/Logs", "Windows/System32/winevt/Logs"),
    ("mk_sysmon_log", "Windows/System32/winevt/Logs", "Windows/System32/winevt/Logs"),
    ("mk_reg_hives", "SYSTEM", "Windows/System32/config/SYSTEM"),
    ("mk_reg_hives", "SOFTWARE", "Windows/System32/config/SOFTWARE"),
    ("mk_reg_hives", "NTUSER.DAT", "Users/alice/NTUSER.DAT"),
    ("mk_execution_artifacts", "SYSTEM", "Windows/System32/config/RegBack/SYSTEM"),
    ("mk_execution_artifacts", "Amcache.hve", "Windows/AppCompat/Programs/Amcache.hve"),
    ("mk_execution_artifacts", "Prefetch", "Windows/Prefetch"),
    ("mk_file_knowledge", "Users", "Users"),
    ("mk_browser_profiles", "Users", "Users"),
]


def merge(src, dst):
    """Move a file or a folder tree into dst, keeping modification times."""
    if os.path.isdir(src):
        for top, _, files in os.walk(src):
            for f in files:
                s = os.path.join(top, f)
                merge(s, os.path.join(dst, os.path.relpath(s, src)))
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst):
        sys.exit(f"{dst} would be written twice")
    shutil.copy2(src, dst)


def main(outdir):
    root = os.path.join(outdir, "C")
    with tempfile.TemporaryDirectory() as tmp:
        for gen in sorted({g for g, _, _ in MOVES}):
            subprocess.run([sys.executable, os.path.join(HERE, gen + ".py"), os.path.join(tmp, gen)],
                           check=True, stdout=subprocess.DEVNULL)
        for gen, src, dst in MOVES:
            merge(os.path.join(tmp, gen, src), os.path.join(root, dst))
    count = sum(len(files) for _, _, files in os.walk(root))
    print(f"{count} files under {root}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
