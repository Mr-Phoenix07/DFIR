#!/usr/bin/env python3
"""parttable.py - decode an MBR and (if present) a GPT from a raw disk image."""
import struct, sys, uuid, zlib

MBR_TYPES = {0x00: "empty", 0x04: "FAT16 <32M", 0x05: "extended", 0x06: "FAT16", 0x07: "NTFS/exFAT",
             0x0B: "FAT32 (CHS)", 0x0C: "FAT32 (LBA)", 0x0F: "extended (LBA)", 0x82: "Linux swap",
             0x83: "Linux", 0x8E: "Linux LVM", 0xEE: "GPT protective", 0xEF: "EFI system"}
GPT_TYPES = {"c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
             "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft basic data",
             "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft reserved",
             "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows recovery",
             "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
             "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
             "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
             "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS"}
SECTOR = 512

def main(path):
    with open(path, "rb") as f:
        mbr = f.read(SECTOR)
        if mbr[510:512] != b"\x55\xaa":
            sys.exit("No 0x55AA boot signature: not an MBR/GPT disk (or not sector 0).")
        print(f"Disk signature: 0x{struct.unpack_from('<I', mbr, 0x1B8)[0]:08x}")
        gpt = False
        for i in range(4):
            e = mbr[0x1BE + 16 * i: 0x1BE + 16 * (i + 1)]
            boot, ptype = e[0], e[4]
            start, count = struct.unpack_from("<II", e, 8)
            if ptype == 0:
                continue
            print(f"MBR #{i+1}: boot=0x{boot:02x} type=0x{ptype:02x} ({MBR_TYPES.get(ptype, '?')}) "
                  f"start LBA={start} sectors={count} -> byte offset {start * SECTOR}")
            gpt |= ptype == 0xEE
        if not gpt:
            return
        f.seek(1 * SECTOR)
        hdr = f.read(92)
        (sig, rev, hsize, hcrc, _, cur, backup, first, last, dguid,
         ent_lba, n_ent, ent_size, ent_crc) = struct.unpack("<8sIIIIQQQQ16sQIII", hdr)
        calc = zlib.crc32(hdr[:16] + b"\0\0\0\0" + hdr[20:hsize]) & 0xFFFFFFFF
        print(f"GPT header: signature={sig!r} revision=0x{rev:08x} size={hsize} "
              f"crc32=0x{hcrc:08x} ({'OK' if calc == hcrc else 'BAD'})")
        print(f"  this LBA={cur} backup LBA={backup} usable LBAs {first}-{last}")
        print(f"  disk GUID={uuid.UUID(bytes_le=dguid)} entries at LBA {ent_lba}: {n_ent} x {ent_size} bytes")
        f.seek(ent_lba * SECTOR)
        for i in range(n_ent):
            e = f.read(ent_size)
            tguid = uuid.UUID(bytes_le=e[0:16])
            if tguid.int == 0:
                continue
            first_lba, last_lba = struct.unpack_from("<QQ", e, 32)
            name = e[56:128].decode("utf-16-le").rstrip("\0")
            print(f"GPT #{i+1}: '{name}' type={GPT_TYPES.get(str(tguid), str(tguid))} "
                  f"LBA {first_lba}-{last_lba} unique GUID={uuid.UUID(bytes_le=e[16:32])}")

if __name__ == "__main__":
    main(sys.argv[1])
