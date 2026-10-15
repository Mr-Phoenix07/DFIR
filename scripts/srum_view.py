#!/usr/bin/env python3
"""srum_view.py - read a SRUM database (SRUDB.dat) on any OS, with dissect.esedb.

Usage: srum_view.py SRUDB.dat                     tables, record counts and time range
       srum_view.py SRUDB.dat --network [N]       top N programs by bytes sent (NetworkUsages)
       srum_view.py SRUDB.dat --app TEXT          every NetworkUsages and AppResourceUseInfo record
                                                  whose program contains TEXT

Needs: pip install dissect.esedb (pure Python). SrumECmd needs Windows' ESE library (esent.dll);
this gives the same tables on Linux and macOS. Table names follow SrumECmd's output files. Program
and user values are resolved through SruDbIdMapTable (programs as paths or service names, users as
SIDs: map SIDs to names with the SOFTWARE hive's ProfileList). Times are UTC.
"""
import argparse
import collections

from dissect.esedb.tools.sru import SRU

TABLES = {  # table GUID -> name used by SrumECmd's CSV files
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "NetworkUsages",
    "{DD6636C4-8929-4683-974E-22C046A43763}": "NetworkConnections",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "AppResourceUseInfo",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": "PushNotifications",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "EnergyUsage",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT": "EnergyUsage (long term)",
    "{5C8CF1C7-7257-4F13-B223-970EF5939312}": "AppTimelineProvider",
    "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}": "vfuprov",
    "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}": "EnergyEstimator",
}
NETWORK = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
RESOURCE = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"


def when(ts):
    return ts.strftime("%Y-%m-%d %H:%M") if ts else "-"


def entries(sru, guid):
    table = sru.get_table(table_guid=guid)
    return list(sru.get_table_entries(table=table)) if table else []


def summary(sru):
    seen = {}   # dissect can list a table name twice (an empty duplicate catalog entry): keep the fuller one
    for t in sru.esedb.tables():
        if t.name.startswith("MSys"):
            continue
        rows = list(t.records())
        span = ""
        if rows and "TimeStamp" in [c.name for c in t.columns]:
            times = sorted(e["TimeStamp"] for e in sru.get_table_entries(table=t))
            span = f"  {when(times[0])} -> {when(times[-1])}"
        if t.name not in seen or len(rows) > seen[t.name][0]:
            seen[t.name] = (len(rows), span)
    for name, (n, span) in seen.items():
        print(f"{TABLES.get(name, name):<24} {n:>5} records{span}")


def network(sru, top):
    total = collections.defaultdict(lambda: [0, 0, 0])
    for e in entries(sru, NETWORK):
        v = total[(e["AppId"], e["UserId"])]
        v[0] += e["BytesSent"] or 0
        v[1] += e["BytesRecvd"] or 0
        v[2] += 1
    print(f"{'BytesSent':>12} {'BytesRecvd':>12} {'Recs':>4}  User / program")
    for (app, user), (sent, recvd, n) in sorted(total.items(), key=lambda kv: (-kv[1][0], str(kv[0])))[:top]:
        print(f"{sent:>12} {recvd:>12} {n:>4}  {user or '-'}  {app or '-'}")


def app(sru, text):
    text = text.lower()
    rows = []
    for e in entries(sru, NETWORK):
        if text in (e["AppId"] or "").lower():
            rows.append((e["TimeStamp"], "NetworkUsages", e["UserId"], e["AppId"],
                         f'sent {e["BytesSent"]} recvd {e["BytesRecvd"]}'))
    for e in entries(sru, RESOURCE):
        if text in (e["AppId"] or "").lower():
            rows.append((e["TimeStamp"], "AppResourceUseInfo", e["UserId"], e["AppId"],
                         f'fg read {e["ForegroundBytesRead"]} written {e["ForegroundBytesWritten"]} '
                         f'| bg read {e["BackgroundBytesRead"]} written {e["BackgroundBytesWritten"]}'))
    for ts, table, user, program, detail in sorted(rows, key=lambda r: (r[0], r[1])):
        print(f"{when(ts)}  {table:<18} {user or '-'}  {program}")
        print(f"{'':18}{detail}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("srudb")
    ap.add_argument("--network", type=int, nargs="?", const=10, metavar="N")
    ap.add_argument("--app", metavar="TEXT")
    args = ap.parse_args()
    with open(args.srudb, "rb") as fh:
        sru = SRU(fh)
        if args.network:
            network(sru, args.network)
        elif args.app:
            app(sru, args.app)
        else:
            summary(sru)


if __name__ == "__main__":
    main()
