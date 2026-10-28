#!/usr/bin/env python3
"""mk_tls_pcap.py - a PCAP with a TLS 1.3 ClientHello for the Day 31 fingerprinting labs.

Usage: python3 mk_tls_pcap.py OUT.pcap

Writes a deterministic libpcap (DLT_EN10MB, valid Ethernet/IPv4/TCP, correct checksums): the TCP
handshake and a real TLS ClientHello from WS-ALICE (10.20.30.40) to the C2 203.0.113.50:443, with
SNI cdn.ws-alice-c2.example. The ClientHello is built to reproduce the worked example in FoxIO's JA4
specification - 15 cipher suites, 16 extensions, ALPN h2, TLS 1.3 via supported_versions - so its
JA4 fingerprint is exactly `t13d1516h2_8daaf6152771_e5627efa2ab1`. That lets you see what TLS still
reveals without decryption (SNI, version, ciphers) and compute a client fingerprint from it.
Teaching traffic, not a real capture. Standard library only.
"""
import struct
import sys

CM = bytes.fromhex("020000000a28")
GW = bytes.fromhex("0200000000fe")
CLIENT = bytes(map(int, "10.20.30.40".split(".")))
C2 = bytes(map(int, "203.0.113.50".split(".")))
SNI = b"cdn.ws-alice-c2.example"
# JA4 spec worked example: 15 ciphers (unsorted, as on the wire)
CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
           0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def csum(d):
    if len(d) % 2:
        d += b"\x00"
    s = sum(struct.unpack(f">{len(d)//2}H", d))
    s = (s >> 16) + (s & 0xFFFF)
    return (~(s + (s >> 16))) & 0xFFFF


def ipv4(src, dst, payload, ident):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, 6, 0, src, dst)
    h = h[:10] + struct.pack(">H", csum(h)) + h[12:]
    return h + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    seg = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 64240, 0, 0) + payload
    pseudo = src + dst + struct.pack(">BBH", 0, 6, len(seg))
    return seg[:16] + struct.pack(">H", csum(pseudo + seg)) + seg[18:]


def ext(etype, body):
    return struct.pack(">HH", etype, len(body)) + body


def client_hello(sni_bytes):
    # extensions, in the JA4 example's on-the-wire order (type codes: 001b 0000 0033 0010 4469
    # 0017 002d 000d 0005 0023 0012 002b ff01 000b 000a 0015)
    sni = struct.pack(">H", len(sni_bytes) + 3) + b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
    alpn_p = b"\x02h2"
    alpn = struct.pack(">H", len(alpn_p)) + alpn_p
    keyshare = struct.pack(">H", 0x001d) + struct.pack(">H", 32) + bytes(32)
    exts = [
        ext(0x001b, b"\x02\x00\x02"),                                   # compress_certificate
        ext(0x0000, sni),                                               # server_name (SNI)
        ext(0x0033, struct.pack(">H", len(keyshare)) + keyshare),       # key_share
        ext(0x0010, alpn),                                              # ALPN
        ext(0x4469, b"\x00"),                                           # application_settings
        ext(0x0017, b""),                                               # extended_master_secret
        ext(0x002d, b"\x01\x01"),                                       # psk_key_exchange_modes
        ext(0x000d, struct.pack(">H", len(SIG_ALGS) * 2) + b"".join(struct.pack(">H", a) for a in SIG_ALGS)),
        ext(0x0005, b"\x01\x00\x00\x00\x00"),                           # status_request
        ext(0x0023, b""),                                               # session_ticket
        ext(0x0012, b""),                                               # signed_certificate_timestamp
        ext(0x002b, b"\x02\x03\x04"),                                   # supported_versions -> TLS 1.3
        ext(0xff01, b"\x00"),                                           # renegotiation_info
        ext(0x000b, b"\x01\x00"),                                       # ec_point_formats
        ext(0x000a, b"\x00\x04\x00\x1d\x00\x17"),                       # supported_groups x25519, secp256r1
        ext(0x0015, bytes(8)),                                          # padding
    ]
    ext_block = b"".join(exts)
    ciphers = b"".join(struct.pack(">H", c) for c in CIPHERS)
    body = (struct.pack(">H", 0x0303) + bytes(32)                       # client_version, random
            + b"\x20" + bytes(32)                                       # session id (32 bytes)
            + struct.pack(">H", len(ciphers)) + ciphers
            + b"\x01\x00"                                               # compression: null
            + struct.pack(">H", len(ext_block)) + ext_block)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body             # handshake: client_hello
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs           # TLS record (handshake, TLS1.0 rec)


def main(out, sni=SNI, dst=C2):
    pkts, t0 = [], 1792000000

    def add(ms, raw):
        pkts.append((t0 + ms // 1000, (ms % 1000) * 1000, raw))

    def frame(smac, dmac, sip, dip, seg, ident):
        return dmac + smac + b"\x08\x00" + ipv4(sip, dip, seg, ident)

    cs, ss = 1000, 5000
    add(0, frame(CM, GW, CLIENT, dst, tcp(CLIENT, dst, 51000, 443, cs, 0, 0x02), 1))
    add(30, frame(GW, CM, dst, CLIENT, tcp(dst, CLIENT, 443, 51000, ss, cs + 1, 0x12), 1))
    add(31, frame(CM, GW, CLIENT, dst, tcp(CLIENT, dst, 51000, 443, cs + 1, ss + 1, 0x10), 2))
    ch = client_hello(sni)
    add(35, frame(CM, GW, CLIENT, dst, tcp(CLIENT, dst, 51000, 443, cs + 1, ss + 1, 0x18, ch), 3))
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for sec, usec, raw in pkts:
            f.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)) + raw)
    print(f"wrote {out}: {len(pkts)} packets (TLS ClientHello, SNI {sni.decode()})")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sni = sys.argv[2].encode() if len(sys.argv) > 2 else SNI
    dst = bytes(map(int, sys.argv[3].split("."))) if len(sys.argv) > 3 else C2
    main(sys.argv[1], sni, dst)
