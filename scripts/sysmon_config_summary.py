#!/usr/bin/env python3
"""sysmon_config_summary.py - summarise a Sysmon configuration file, or list one event type's rules.

Usage: sysmon_config_summary.py CONFIG.xml                 what each event type collects
       sysmon_config_summary.py CONFIG.xml --show TAG      the rules of one filter tag (e.g. FileCreateTime)

For each filter tag (ProcessCreate, NetworkConnect, ...) it counts the rules in the include and the
exclude filters and says what that means, following Sysmon's documented semantics:
  include with rules     only events matching a rule are logged
  include with no rules  nothing is logged (an empty include matches nothing)
  exclude with rules     everything is logged except events matching a rule (exclude wins over include)
  exclude with no rules  everything is logged
Tags the file does not mention keep Sysmon's default behaviour (see `sysmon -s` and the docs).
A <Rule groupRelation="and"> inside a filter counts as one rule.
"""
import sys
import xml.etree.ElementTree as ET

ORDER = ["ProcessCreate", "FileCreateTime", "NetworkConnect", "ProcessTerminate", "DriverLoad", "ImageLoad",
         "CreateRemoteThread", "RawAccessRead", "ProcessAccess", "FileCreate", "RegistryEvent",
         "FileCreateStreamHash", "PipeEvent", "WmiEvent", "DnsQuery", "FileDelete", "ClipboardChange",
         "ProcessTampering", "FileDeleteDetected", "FileBlockExecutable", "FileBlockShredding",
         "FileExecutableDetected"]


def filters(root):
    """Yield (tag, onmatch, group relation, rule elements) for every filter under EventFiltering."""
    ef = root.find("EventFiltering")
    for node in list(ef) if ef is not None else []:
        if node.tag == "RuleGroup":
            for f in node:
                yield f.tag, f.get("onmatch", "include"), node.get("groupRelation", "or"), list(f)
        else:
            yield node.tag, node.get("onmatch", "include"), "or", list(node)


def summary(root):
    print(f'schemaversion {root.get("schemaversion")}')
    for child in root:
        if child.tag != "EventFiltering":
            print(f"{child.tag:<16} {(child.text or '').strip() or '(present, no value)'}")
    seen = {}
    for tag, onmatch, _, rules in filters(root):
        seen.setdefault(tag, {"include": None, "exclude": None})
        prev = seen[tag][onmatch] or 0
        seen[tag][onmatch] = prev + len(rules)
    print(f"\n{'Filter tag':<22} {'include':>7} {'exclude':>7}  meaning")
    for tag in sorted(seen, key=lambda t: ORDER.index(t) if t in ORDER else 99):
        inc, exc = seen[tag]["include"], seen[tag]["exclude"]
        if exc:
            meaning = "everything except the exclude rules"
            if inc:
                meaning = "only include matches, minus exclude matches"
        elif inc:
            meaning = "only events matching an include rule"
        elif inc == 0 and exc is None:
            meaning = "nothing (empty include)"
        else:
            meaning = "everything (empty exclude)"
        print(f"{tag:<22} {'-' if inc is None else inc:>7} {'-' if exc is None else exc:>7}  {meaning}")
    missing = [t for t in ORDER if t not in seen]
    print("\nnot mentioned (Sysmon default):", ", ".join(missing))


def show(root, wanted):
    for tag, onmatch, relation, rules in filters(root):
        if tag != wanted:
            continue
        print(f"{tag} onmatch={onmatch} (rules combined with {relation.upper()})")
        for r in rules:
            if r.tag == "Rule":
                parts = " AND ".join(f'{c.tag} {c.get("condition", "is")} "{c.text}"' for c in r)
                print(f'    [{r.get("name", "")}] {parts}')
            else:
                name = f'[{r.get("name")}] ' if r.get("name") else ""
                print(f'    {name}{r.tag} {r.get("condition", "is")} "{r.text}"')


def main(args):
    if len(args) not in (1, 3) or (len(args) == 3 and args[1] != "--show"):
        sys.exit(__doc__)
    root = ET.parse(args[0]).getroot()
    if len(args) == 1:
        summary(root)
    else:
        show(root, args[2])


if __name__ == "__main__":
    main(sys.argv[1:])
