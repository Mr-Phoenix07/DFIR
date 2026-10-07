#!/usr/bin/env python3
"""tkape_collect.py - a small teaching re-implementation of KAPE *Target* processing.

It reads KAPE Target files (.tkape YAML, e.g. from github.com/EricZimmerman/KapeFiles),
expands compound Targets, resolves their Windows paths against a folder that stands in for
C:\\ (a mounted image, for example), and copies what matches into --tdest. Like KAPE it
re-creates directories, de-duplicates by SHA-1 and writes a copy log and a skip log.

This is NOT KAPE. It cannot read locked files, does not use Volume Shadow Copies, and has
no Modules, containers or uploads. Use it on Linux or macOS to learn how Targets work and
to test Targets you write. Use kape.exe for real Windows collections.

Usage:
  tkape_collect.py --targets DIR --tlist [WORD]          list Targets (optionally filtered)
  tkape_collect.py --targets DIR --tdetail NAME          show every path a Target expands to
  tkape_collect.py --targets DIR --check FILE.tkape      lint a Target you wrote
  tkape_collect.py --targets DIR --tsource ROOT --target NAME[,NAME] --tdest OUT
                   [--tvars user:alice] [--tdd false] [--dry-run]

Requires PyYAML (Debian/Ubuntu: apt install python3-yaml).
"""
import argparse
import csv
import datetime as dt
import fnmatch
import hashlib
import os
import re
import shutil
import sys
import uuid

import yaml

REQUIRED_TOP = ["Description", "Author", "Version", "Id", "RecreateDirectories", "Targets"]
REQUIRED_ENTRY = ["Name", "Category", "Path"]
COPY_FIELDS = ["CopiedTimestamp", "SourceFile", "DestinationFile", "FileSize", "SourceFileSha1",
               "DeferredCopy", "CreatedOnUtc", "ModifiedOnUtc", "LastAccessedOnUtc", "CopyDuration"]
SKIP_FIELDS = ["SourceFile", "SourceFileSha1", "Reason"]


def load(path):
    with open(path, encoding="utf-8-sig") as f:
        return yaml.safe_load(f)


def index_targets(root):
    """Map lower-case Target name -> file, and lower-case sub-folder -> [files]. Skips !Disabled."""
    by_name, by_dir = {}, {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d.lower() != "!disabled")
        for fn in sorted(filenames):
            if fn.lower().endswith(".tkape"):
                full = os.path.join(dirpath, fn)
                by_name.setdefault(fn[:-6].lower(), full)
                rel = os.path.relpath(dirpath, root)
                if rel != ".":
                    by_dir.setdefault(rel.replace(os.sep, "/").lower(), []).append(full)
    return by_name, by_dir


def expand(names, by_name, by_dir, warn):
    """Return leaf entries [(target_name, entry)] for the given Target names, compound ones expanded."""
    seen_ids, leaves = set(), []

    def visit(path):
        doc = load(path)
        tid = str(doc.get("Id", path)).lower()
        if tid in seen_ids:  # KAPE uses Id so a Target pulled in twice only runs once
            return
        seen_ids.add(tid)
        tname = os.path.basename(path)[:-6]
        for entry in doc.get("Targets") or []:
            p = str(entry.get("Path", ""))
            if p.lower().endswith(".tkape"):
                ref = by_name.get(p[:-6].lower())
                if ref:
                    visit(ref)
                else:
                    warn(f"{tname}: referenced Target '{p}' not found")
            elif re.fullmatch(r"[^:\\]+\\\*", p):  # e.g. 'Antivirus\*' = every Target in that folder
                for ref in by_dir.get(p[:-2].replace("\\", "/").lower(), []):
                    visit(ref)
            else:
                leaves.append((tname, entry))

    for n in names:
        if n.lower() in by_name:
            visit(by_name[n.lower()])
        elif n.replace("\\", "/").lower() in by_dir:  # --target Windows = every Target in Targets/Windows
            for ref in by_dir[n.replace("\\", "/").lower()]:
                visit(ref)
        else:
            sys.exit(f"Target '{n}' not found (try --tlist)")
    return leaves


def ci_child(parent, name):
    """Case-insensitive lookup of one directory entry, like Windows does."""
    try:
        for e in os.listdir(parent):
            if e.lower() == name.lower():
                return os.path.join(parent, e)
    except OSError:
        pass
    return None


def resolve_dirs(tsource, winpath, tvars):
    path = re.sub(r"%user%", tvars.get("user", "*"), winpath, flags=re.I)
    path = re.sub(r"^[A-Za-z]:\\?", "", path)
    dirs = [tsource]
    for seg in [s for s in path.split("\\") if s]:
        nxt = []
        for d in dirs:
            if any(c in seg for c in "*?["):
                try:
                    kids = sorted(os.listdir(d))
                except OSError:
                    kids = []
                nxt += [os.path.join(d, k) for k in kids
                        if fnmatch.fnmatch(k.lower(), seg.lower()) and os.path.isdir(os.path.join(d, k))]
            else:
                hit = ci_child(d, seg)
                if hit and os.path.isdir(hit):
                    nxt.append(hit)
        dirs = nxt
    return dirs


def mask_matcher(mask):
    if mask.lower().startswith("regex:"):
        return re.compile(r"\A(?:" + mask[6:] + r")\Z", re.I).match
    return lambda name: fnmatch.fnmatch(name.lower(), mask.lower())


def resolve(entry, tsource, tvars, warn):
    """Yield source files for one leaf entry."""
    mask = str(entry.get("FileMask", "*"))
    try:
        match = mask_matcher(mask)
    except re.error as e:
        warn(f"{entry.get('Name')}: bad regex FileMask {mask!r} ({e}); entry skipped")
        return
    literal = not mask.lower().startswith("regex:") and not any(c in mask for c in "*?[")
    lo, hi = entry.get("MinSize"), entry.get("MaxSize")
    for d in resolve_dirs(tsource, str(entry["Path"]), tvars):
        found = []
        if literal:
            # Direct open, not a directory listing: this is how hidden NTFS metadata files
            # ($MFT, $LogFile) and streams such as $UsnJrnl:$J are reached (AlwaysAddToQueue).
            direct = os.path.join(d, mask)
            found = [direct] if os.path.isfile(direct) else [p for p in [ci_child(d, mask)] if p and os.path.isfile(p)]
        elif entry.get("Recursive"):
            for dp, dn, fns in os.walk(d):
                dn.sort()
                found += [os.path.join(dp, f) for f in sorted(fns) if match(f)]
        else:
            try:
                found = [os.path.join(d, f) for f in sorted(os.listdir(d))
                         if match(f) and os.path.isfile(os.path.join(d, f))]
            except OSError:
                pass
        for f in found:
            size = os.path.getsize(f)
            if (lo is not None and size < lo) or (hi is not None and size > hi):
                continue
            yield f


def winpath(tsource, path):
    rel = os.path.relpath(path, tsource)
    return "C:\\" + ("" if rel == "." else rel.replace(os.sep, "\\"))


def utc(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def ntfs_crtime(path):
    """Creation time from ntfs-3g's system.ntfs_crtime extended attribute, if available."""
    try:
        raw = os.getxattr(path, "system.ntfs_crtime")
        return utc(int.from_bytes(raw[:8], "little") / 10_000_000 - 11644473600)
    except (OSError, AttributeError):
        return ""


def sha1(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest().upper()


def collect(args, by_name, by_dir, warn):
    names = [n for n in args.target.split(",") if n]
    tvars = dict(kv.split(":", 1) for kv in args.tvars.split("^")) if args.tvars else {}
    leaves = expand(names, by_name, by_dir, warn)
    tsource = os.path.abspath(args.tsource)
    queue, queued = [], set()
    for tname, entry in leaves:
        for src in resolve(entry, tsource, tvars, warn):
            if src not in queued:
                queued.add(src)
                queue.append((tname, entry, src))
    print(f"{len(leaves)} file specifications from {len(names)} Target(s); {len(queue)} files queued")
    if args.dry_run:
        for tname, entry, src in queue:
            print(f"  [{entry.get('Category')}] {winpath(tsource, src)}")
        return 0
    started = dt.datetime.now(dt.timezone.utc)
    stamp = started.strftime("%Y-%m-%dT%H_%M_%S_%f")
    label = names[0] if len(names) == 1 else "(Multiple)"
    os.makedirs(args.tdest, exist_ok=True)
    seen, copied, skipped, total = set(), 0, 0, 0
    with open(os.path.join(args.tdest, f"{stamp}_{label}_CopyLog.csv"), "w", newline="") as cf, \
         open(os.path.join(args.tdest, f"{stamp}_{label}_SkipLog.csv"), "w", newline="") as sf:
        cw, sw = csv.writer(cf), csv.writer(sf)
        cw.writerow(COPY_FIELDS)
        sw.writerow(SKIP_FIELDS)
        for tname, entry, src in queue:
            digest = sha1(src)
            if args.tdd and digest in seen:
                sw.writerow([winpath(tsource, src), digest, "Deduped"])
                skipped += 1
                continue
            seen.add(digest)
            rel = os.path.relpath(src, tsource)
            name = entry.get("SaveAsFileName") or os.path.basename(rel)
            base = os.path.join(os.path.abspath(args.tdest), "C")
            dest = os.path.join(base, os.path.dirname(rel), name) if load_recreate(by_name, tname) else os.path.join(base, name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            t0 = dt.datetime.now()
            st = os.stat(src)
            try:
                shutil.copyfile(src, dest)
                os.utime(dest, ns=(st.st_atime_ns, st.st_mtime_ns))  # keep accessed/modified times on the copy
            except OSError as e:
                sw.writerow([winpath(tsource, src), digest, f"Error: {e.strerror}"])
                skipped += 1
                continue
            cw.writerow([dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f"),
                         winpath(tsource, src), dest, st.st_size, digest, False, ntfs_crtime(src),
                         utc(st.st_mtime), utc(st.st_atime), str(dt.datetime.now() - t0)])
            copied += 1
            total += st.st_size
    print(f"Copied {copied} files ({total} bytes), skipped {skipped} (see SkipLog) -> {args.tdest}")
    return 0


_recreate_cache = {}


def load_recreate(by_name, tname):
    if tname not in _recreate_cache:
        _recreate_cache[tname] = bool(load(by_name[tname.lower()]).get("RecreateDirectories", True))
    return _recreate_cache[tname]


def tlist(by_name, word):
    for name, path in sorted(by_name.items()):
        doc = load(path)
        line = f"{os.path.basename(path)[:-6]:<40} {doc.get('Description', '')}"
        if not word or word.lower() in line.lower():
            print(line)
    return 0


def tdetail(args, by_name, by_dir, warn):
    for tname, e in expand(args.tdetail.split(","), by_name, by_dir, warn):
        extra = " (recursive)" if e.get("Recursive") else ""
        print(f"{tname:<22} {str(e.get('Category')):<14} {e['Path']}  {e.get('FileMask', '*')}{extra}")
    return 0


def check(path, by_name, by_dir):
    errors, warns = [], []
    try:
        doc = load(path)
    except yaml.YAMLError as e:
        print(f"ERROR  not valid YAML: {e}")
        return 1
    if not isinstance(doc, dict):
        print("ERROR  top level is not a mapping")
        return 1
    errors += [f"missing required field '{k}'" for k in REQUIRED_TOP if k not in doc]
    try:
        uuid.UUID(str(doc.get("Id")))
    except ValueError:
        errors.append(f"Id {doc.get('Id')!r} is not a GUID")
    me = os.path.abspath(path)
    for other in by_name.values():
        if os.path.abspath(other) != me and str(load(other).get("Id", "")).lower() == str(doc.get("Id")).lower():
            errors.append(f"Id already used by {other}")
    entries = doc.get("Targets") or []
    if not entries:
        errors.append("Targets list is empty")
    for i, e in enumerate(entries, 1):
        errors += [f"entry {i}: missing '{k}'" for k in REQUIRED_ENTRY if k not in e]
        p = str(e.get("Path", ""))
        if p.lower().endswith(".tkape"):
            if p[:-6].lower() not in by_name:
                errors.append(f"entry {i}: referenced Target '{p}' not found")
        elif not re.match(r"^[A-Za-z]:\\", p) and not re.fullmatch(r"[^:\\]+\\\*", p):
            errors.append(f"entry {i}: Path should start with C:\\ (got {p!r})")
        elif not p.endswith("\\") and not p.endswith("*"):
            warns.append(f"entry {i}: directory Path should end with a backslash")
        m = str(e.get("FileMask", "*"))
        if m.lower().startswith("regex:"):
            try:
                re.compile(m[6:])
            except re.error as ex:
                errors.append(f"entry {i}: FileMask regex does not compile ({ex})")
    for w in warns:
        print(f"WARN   {w}")
    for e in errors:
        print(f"ERROR  {e}")
    print(f"{os.path.basename(path)}: {len(entries)} entries, {len(errors)} error(s), {len(warns)} warning(s)")
    return 1 if errors else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--targets", required=True, help="folder holding .tkape files (searched recursively)")
    ap.add_argument("--tlist", nargs="?", const="", metavar="WORD")
    ap.add_argument("--tdetail", metavar="NAME")
    ap.add_argument("--check", metavar="FILE")
    ap.add_argument("--tsource")
    ap.add_argument("--target")
    ap.add_argument("--tdest")
    ap.add_argument("--tvars", help="e.g. user:alice (replaces %%user%%, default *)")
    ap.add_argument("--tdd", default="true", choices=["true", "false"], help="SHA-1 de-duplication")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    args.tdd = args.tdd == "true"
    by_name, by_dir = index_targets(args.targets)
    if args.check and os.path.basename(args.check)[:-6].lower() not in by_name:
        by_name[os.path.basename(args.check)[:-6].lower()] = args.check
    warn = lambda msg: print(f"WARN   {msg}", file=sys.stderr)  # noqa: E731
    if args.tlist is not None:
        return tlist(by_name, args.tlist)
    if args.tdetail:
        return tdetail(args, by_name, by_dir, warn)
    if args.check:
        return check(args.check, by_name, by_dir)
    if not (args.tsource and args.target and args.tdest):
        ap.error("collection needs --tsource, --target and --tdest")
    return collect(args, by_name, by_dir, warn)


if __name__ == "__main__":
    sys.exit(main())
