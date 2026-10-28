#!/usr/bin/env python3
"""ja_fingerprint.py - compute JA3 and JA4 TLS client fingerprints from a ClientHello in a PCAP.

Usage: ja_fingerprint.py FILE.pcap

Even when you can't decrypt TLS, the ClientHello is in the clear and is highly characteristic of the
client software. This parses the first TLS ClientHello in a capture and prints:
  * the SNI, TLS version and cipher list it advertised (what the handshake reveals);
  * its JA3 (salesforce) fingerprint: SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats -> MD5;
  * its JA4 (FoxIO) fingerprint: a_b_c, with GREASE ignored, per the published spec.

Two malware samples behind ever-changing C2 IPs/domains often share one client fingerprint, so a
JA3/JA4 is a durable IOC. A match is a lead - benign tools share fingerprints too. Standard library
only; DLT_EN10MB, single-segment ClientHello.
"""
import hashlib
import struct
import sys


def is_grease(v):
    return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)


def tcp_payloads(path):
    data = open(path, "rb").read()
    le = data[:4] == b"\xd4\xc3\xb2\xa1"
    e = "<" if le else ">"
    off = 24
    while off + 16 <= len(data):
        _, _, caplen, _ = struct.unpack_from(e + "IIII", data, off)
        off += 16
        pkt, off = data[off:off + caplen], off + caplen
        if len(pkt) < 54 or pkt[12:14] != b"\x08\x00":
            continue
        ihl = (pkt[14] & 0x0F) * 4
        if pkt[23] != 6:
            continue
        thl = ((pkt[14 + ihl + 12] >> 4) & 0xF) * 4
        yield pkt[14 + ihl + thl:]


def find_client_hello(path):
    for pl in tcp_payloads(path):
        if len(pl) > 5 and pl[0] == 0x16 and pl[5] == 0x01:   # TLS handshake record, client_hello
            rec_len = struct.unpack_from(">H", pl, 3)[0]
            return pl[5:5 + rec_len]
    sys.exit("no TLS ClientHello found")


def parse(ch):
    hs_len = int.from_bytes(ch[1:4], "big")
    b = ch[4:4 + hs_len]
    ver = struct.unpack_from(">H", b, 0)[0]
    p = 2 + 32
    sid_len = b[p]; p += 1 + sid_len
    cs_len = struct.unpack_from(">H", b, p)[0]; p += 2
    ciphers = [struct.unpack_from(">H", b, p + 2 * i)[0] for i in range(cs_len // 2)]; p += cs_len
    comp_len = b[p]; p += 1 + comp_len
    ext_total = struct.unpack_from(">H", b, p)[0]; p += 2
    end = p + ext_total
    exts, groups, formats, sigs, alpn, supv, sni = [], [], [], [], None, [], None
    while p < end:
        et, el = struct.unpack_from(">HH", b, p); p += 4
        body = b[p:p + el]; p += el
        exts.append(et)
        if et == 0x0000:
            nlen = struct.unpack_from(">H", body, 3)[0]
            sni = body[5:5 + nlen].decode("latin-1")
        elif et == 0x000a:
            n = struct.unpack_from(">H", body, 0)[0]
            groups = [struct.unpack_from(">H", body, 2 + 2 * i)[0] for i in range(n // 2)]
        elif et == 0x000b:
            formats = list(body[1:1 + body[0]])
        elif et == 0x000d:
            n = struct.unpack_from(">H", body, 0)[0]
            sigs = [struct.unpack_from(">H", body, 2 + 2 * i)[0] for i in range(n // 2)]
        elif et == 0x0010:
            first = body[3:3 + body[2]]
            alpn = first
        elif et == 0x002b:
            supv = [struct.unpack_from(">H", body, 1 + 2 * i)[0] for i in range(body[0] // 2)]
    return dict(ver=ver, ciphers=ciphers, exts=exts, groups=groups, formats=formats,
                sigs=sigs, alpn=alpn, supv=supv, sni=sni)


def ja3(h):
    ng = lambda xs: [x for x in xs if not is_grease(x)]  # noqa: E731
    s = ",".join(["-".join(str(x) for x in grp) for grp in
                  ([h["ver"]], ng(h["ciphers"]), ng(h["exts"]), ng(h["groups"]), h["formats"])])
    return s, hashlib.md5(s.encode()).hexdigest()


VERMAP = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}


def ja4(h):
    ng = lambda xs: [x for x in xs if not is_grease(x)]  # noqa: E731
    ver = max([v for v in h["supv"] if not is_grease(v)], default=h["ver"]) if h["supv"] else h["ver"]
    v = VERMAP.get(ver, "00")
    sni = "d" if h["sni"] else "i"
    nc, ne = len(ng(h["ciphers"])), len(ng(h["exts"]))
    if h["alpn"]:
        a = h["alpn"]
        def pc(byte):  # printable alnum else hex nibble
            return chr(byte) if (0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5a or 0x61 <= byte <= 0x7a) else None
        f, l = pc(a[0]), pc(a[-1])
        alpn = (f or format(a[0], "02x")[0]) + (l or format(a[-1], "02x")[-1]) if (f and l) else \
               (format(a[0], "02x")[0] + format(a[-1], "02x")[-1])
    else:
        alpn = "00"
    a_ = f"t{v}{sni}{min(nc,99):02d}{min(ne,99):02d}{alpn}"
    ciph = ",".join(f"{c:04x}" for c in sorted(ng(h["ciphers"])))
    b_ = hashlib.sha256(ciph.encode()).hexdigest()[:12] if ciph else "000000000000"
    extl = sorted(e for e in ng(h["exts"]) if e not in (0x0000, 0x0010))
    exts = ",".join(f"{e:04x}" for e in extl)
    if h["sigs"]:
        exts += "_" + ",".join(f"{s:04x}" for s in h["sigs"])
    c_ = hashlib.sha256(exts.encode()).hexdigest()[:12] if extl else "000000000000"
    return f"{a_}_{b_}_{c_}"


def main(path):
    h = parse(find_client_hello(path))
    ng = [c for c in h["ciphers"] if not is_grease(c)]
    print(f"SNI:      {h['sni'] or '(none)'}")
    print(f"version:  0x{(max(h['supv']) if h['supv'] else h['ver']):04x} (TLS {VERMAP.get(max(h['supv']) if h['supv'] else h['ver'],'?')})")
    print(f"ciphers:  {len(ng)} offered")
    s, j3 = ja3(h)
    print(f"JA3:      {j3}")
    print(f"JA4:      {ja4(h)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
