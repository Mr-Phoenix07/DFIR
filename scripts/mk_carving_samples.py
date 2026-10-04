#!/usr/bin/env python3
"""mk_carving_samples.py - write deterministic sample files for file-carving labs.

Usage: python3 mk_carving_samples.py OUTDIR

Creates (always byte-identical, standard library only):
  photo.jpg       valid baseline JPEG, ~6 KB (comment segments as padding)
  vacation.jpg    valid baseline JPEG, ~12 KB (used for the fragmentation demo)
  diagram.png     valid 64x64 RGB PNG, ~12 KB (pseudo-random pixels)
  report.pdf      small valid PDF with one text page
  notes.docx      minimal Word document (a ZIP container)
"""
import os
import struct
import sys
import zipfile
import zlib


def _seg(marker, payload):
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def tiny_jpeg(comment_kb, tag):
    """A valid 8x8 grey baseline JPEG, padded with `comment_kb` 1 KiB COM segments."""
    out = b"\xff\xd8"                                                       # SOI
    out += _seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")      # APP0 JFIF
    for i in range(comment_kb):                                             # COM padding
        out += _seg(0xFE, (tag + b" %04d " % i).ljust(1024, b"."))
    out += _seg(0xDB, b"\x00" + b"\x01" * 64)                               # DQT
    out += _seg(0xC0, b"\x08\x00\x08\x00\x08\x01\x01\x11\x00")              # SOF0 8x8, 1 component
    out += _seg(0xC4, b"\x00" + bytes([1] + [0] * 15) + b"\x00")            # DHT DC: 1 code -> cat 0
    out += _seg(0xC4, b"\x10" + bytes([1] + [0] * 15) + b"\x00")            # DHT AC: 1 code -> EOB
    out += _seg(0xDA, b"\x01\x01\x00\x00\x3f\x00")                         # SOS
    out += b"\x3f"                                                          # DC=0, EOB, padding
    out += b"\xff\xd9"                                                      # EOI
    return out


def png(width, height, seed):
    """A valid RGB PNG with deterministic pseudo-random pixels (barely compressible)."""
    state = seed
    rows = b""
    for _ in range(height):
        row = bytearray([0])                                                # filter: none
        for _ in range(width * 3):
            state = (1103515245 * state + 12345) & 0x7FFFFFFF               # simple LCG
            row.append(state >> 23 & 0xFF)
        rows += bytes(row)

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9))
            + chunk(b"IEND", b""))


def pdf(text):
    """A small, valid one-page PDF."""
    stream = b"BT /F1 18 Tf 72 720 Td (" + text + b") Tj ET"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


def docx(path, text):
    """A minimal Word document; fixed timestamps keep the ZIP byte-identical."""
    parts = {
        "[Content_Types].xml":
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels":
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>',
        "word/document.xml":
            '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>" + text + "</w:t></w:r></w:p></w:body></w:document>",
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 9, 30, 17, 45, 10))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    files = {
        "photo.jpg": tiny_jpeg(6, b"holiday photo"),
        "vacation.jpg": tiny_jpeg(12, b"vacation photo"),
        "diagram.png": png(64, 64, seed=2026),
        "report.pdf": pdf(b"Q3 acquisition targets - CONFIDENTIAL"),
    }
    for name, data in files.items():
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)
    docx(os.path.join(outdir, "notes.docx"), "Meeting notes: move funds before audit")
    for name in sorted(os.listdir(outdir)):
        print(f"{os.path.getsize(os.path.join(outdir, name)):>7}  {name}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "samples")
