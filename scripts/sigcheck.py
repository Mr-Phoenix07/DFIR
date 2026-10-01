#!/usr/bin/env python3
"""sigcheck.py - flag files whose magic bytes don't match their extension."""
import os, sys

SIGNATURES = [  # (offset, magic bytes, type, extensions that are consistent with it)
    (0, b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
    (0, b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
    (0, b"GIF8", "GIF image", {".gif"}),
    (0, b"%PDF", "PDF document", {".pdf"}),
    (0, b"PK\x03\x04", "ZIP container", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt"}),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 (legacy Office/MSG)", {".doc", ".xls", ".ppt", ".msg"}),
    (0, b"Rar!\x1a\x07", "RAR archive", {".rar"}),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {".7z"}),
    (0, b"\x1f\x8b", "gzip", {".gz", ".tgz"}),
    (0, b"MZ", "Windows PE executable", {".exe", ".dll", ".sys", ".scr", ".cpl"}),
    (0, b"\x7fELF", "ELF executable", {"", ".so", ".bin", ".elf"}),
    (0, b"SQLite format 3\x00", "SQLite database", {".db", ".sqlite", ".sqlite3"}),
    (0, b"regf", "Windows registry hive", {"", ".dat", ".hve"}),
    (0, b"ElfFile\x00", "Windows event log (EVTX)", {".evtx"}),
    (0, b"EVF\x09\x0d\x0a\xff\x00", "EnCase image (E01)", {".e01"}),
    (4, b"ftyp", "MP4/MOV/HEIC (ISO media)", {".mp4", ".mov", ".m4a", ".heic", ".3gp"}),
]

def check(path):
    with open(path, "rb") as f:
        head = f.read(32)
    ext = os.path.splitext(path)[1].lower()
    for off, magic, kind, exts in SIGNATURES:
        if head[off:off + len(magic)] == magic:
            status = "ok" if ext in exts else "MISMATCH"
            return f"{status:8}  {path}  ->  {kind}"
    return f"{'unknown':8}  {path}  ->  no known signature"

for root, _, files in os.walk(sys.argv[1] if len(sys.argv) > 1 else "."):
    for name in sorted(files):
        print(check(os.path.join(root, name)))
