#!/usr/bin/env python3
"""msg_props.py - show what is inside an Outlook .msg file: streams, key MAPI properties, times, attachments.

Usage: msg_props.py MESSAGE.msg [MESSAGE2.msg ...]       (needs: pip install olefile)

A .msg file is a Compound File (OLE/CFB, like old .doc files) holding one message's MAPI properties:
  __substg1.0_PPPPTTTT          a variable-length property: PPPP = property ID, TTTT = type
                                (001F Unicode string, 001E 8-bit string, 0102 binary)
  __properties_version1.0       the fixed-length properties (times, flags, sizes), 16 bytes each:
                                tag (type + ID), flags, 8-byte value; after a 32-byte header in the
                                message itself and an 8-byte header in recipients and attachments
  __recip_version1.0_#NNNNNNNN  one storage per recipient
  __attach_version1.0_#NNNNNNNN one storage per attachment (data in __substg1.0_37010102)
  __nameid_version1.0           the named-property mapping
Times are FILETIMEs (100 ns since 1601, UTC).
"""
import datetime
import struct
import sys

import olefile

STRINGS = [  # (property ID, name)
    (0x0037, "Subject"), (0x0C1A, "Sender name"), (0x0C1F, "Sender address"), (0x0065, "Sent-repr. address"),
    (0x0E04, "Display To"), (0x0E03, "Display Cc"), (0x1035, "Internet Message-ID"),
    (0x007D, "Transport headers"), (0x1000, "Body (plain text)"),
]
TIMES = {0x0039: "Client submit time", 0x0E06: "Delivery time", 0x3007: "Creation time",
         0x3008: "Last modification time"}


def text(ole, storage, prop):
    for kind, codec in (("001F", "utf-16-le"), ("001E", "cp1252")):
        path = storage + [f"__substg1.0_{prop:04X}{kind}"]
        if ole.exists("/".join(path)):
            return ole.openstream(path).read().decode(codec, "replace").rstrip("\0")
    return None


def fixed(ole, storage, header):
    path = storage + ["__properties_version1.0"]
    if not ole.exists("/".join(path)):
        return {}
    data = ole.openstream(path).read()
    props = {}
    for off in range(header, len(data) - 15, 16):
        tag, _flags, value = struct.unpack_from("<IIQ", data, off)
        props[tag >> 16] = (tag & 0xFFFF, value)
    return props


def filetime(v):
    return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)).strftime("%Y-%m-%d %H:%M:%S")


def show(path):
    ole = olefile.OleFileIO(path)
    entries = ole.listdir(streams=True, storages=True)
    recips = sorted({e[0] for e in entries if e[0].startswith("__recip_version1.0_")})
    attachs = sorted({e[0] for e in entries if e[0].startswith("__attach_version1.0_")})
    print(f"== {path}: {len(ole.listdir())} streams, {len(recips)} recipient(s), {len(attachs)} attachment(s)")
    for prop, name in STRINGS:
        value = text(ole, [], prop)
        if value is not None:
            first = value.splitlines()[0] if value.strip() else ""
            more = f"  (+{len(value.splitlines()) - 1} more lines)" if len(value.splitlines()) > 1 else ""
            print(f"  {name:<22} {first[:70]}{more}")
    for prop, (ptype, value) in sorted(fixed(ole, [], 32).items()):
        if prop in TIMES and ptype == 0x0040:
            print(f"  {TIMES[prop]:<22} {filetime(value)} UTC")
    for a in attachs:
        name = text(ole, [a], 0x3707) or text(ole, [a], 0x3704) or "?"
        data = [a, "__substg1.0_37010102"]
        size = ole.get_size("/".join(data)) if ole.exists("/".join(data)) else 0
        mime = text(ole, [a], 0x370E) or "-"
        print(f"  attachment {a[-8:]}  {size:>7} bytes  {mime:<24} {name}")
    ole.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for p in sys.argv[1:]:
        show(p)
