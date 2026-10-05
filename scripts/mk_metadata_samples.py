#!/usr/bin/env python3
"""mk_metadata_samples.py - write deterministic sample files for metadata and bulk-extraction labs.

Usage: python3 mk_metadata_samples.py OUTDIR

Creates (byte-identical on every run, standard library only):
  IMG_2041.jpg      small valid JPEG with no metadata yet (add EXIF with ExifTool in the lab)
  contract.docx     Word document with core.xml / app.xml properties (author, editor, times, company)
  invoice.pdf       PDF with a document-information dictionary (author, creator, producer, dates)
  notes.txt         plain text with emails, URLs, a fictional 555-01xx phone number, an IP and published payment-card TEST numbers
  backup.zip        ZIP whose (compressed) member contains an email address and a URL
  blob.b64          base64-encoded text containing an email address
  mystery.bin       a PNG with a misleading name and no extension hint
"""
import base64
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mk_carving_samples import png, tiny_jpeg  # noqa: E402  (same folder)

FIXED = (2026, 9, 30, 17, 45, 10)


def zip_write(path, members):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=FIXED)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)


def docx(path):
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        "<dc:title>Supply agreement - DRAFT</dc:title>"
        "<dc:creator>M. Rivera</dc:creator>"
        "<cp:lastModifiedBy>J. Chen</cp:lastModifiedBy>"
        "<cp:revision>7</cp:revision>"
        '<dcterms:created xsi:type="dcterms:W3CDTF">2026-09-14T08:02:00Z</dcterms:created>'
        '<dcterms:modified xsi:type="dcterms:W3CDTF">2026-09-29T23:41:00Z</dcterms:modified>'
        "</cp:coreProperties>"
    )
    app = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        "<Template>Normal.dotm</Template><TotalTime>412</TotalTime>"
        "<Application>Microsoft Office Word</Application><Company>Northwind Traders</Company>"
        "<AppVersion>16.0000</AppVersion></Properties>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
        "</Relationships>"
    )
    body = (
        '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>Send the signed copy to j.chen@northwind-traders.com before Friday.</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )
    zip_write(path, {"[Content_Types].xml": content_types, "_rels/.rels": rels,
                     "docProps/core.xml": core, "docProps/app.xml": app, "word/document.xml": body})


def pdf_with_info(path):
    stream = b"BT /F1 18 Tf 72 720 Td (Invoice 2026-0412: 48,500 EUR) Tj ET"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Title (Invoice 2026-0412) /Author (M. Rivera) /Creator (Microsoft Word) "
        b"/Producer (Microsoft: Print To PDF) /CreationDate (D:20260930101500+02'00') "
        b"/ModDate (D:20260930101500+02'00') >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    with open(path, "wb") as f:
        f.write(out)


NOTES = """Call notes - 2026-09-29
Contact: maria.rivera@northwind-traders.com / backup: m.rivera.private@example.org
Phone: +1 (555) 010-4477
Portal: https://portal.northwind-traders.com/login?next=/payments
Exfil server seen in proxy logs: http://203.0.113.50/upload.php
Hotel card on file (published Discover TEST number): 6011000990139424
Visa TEST number from the booking email: 4000 0566 5566 5556
"""


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "IMG_2041.jpg"), "wb") as f:
        f.write(tiny_jpeg(0, b""))
    docx(os.path.join(outdir, "contract.docx"))
    pdf_with_info(os.path.join(outdir, "invoice.pdf"))
    with open(os.path.join(outdir, "notes.txt"), "w") as f:
        f.write(NOTES)
    zip_write(os.path.join(outdir, "backup.zip"),
              {"secret/plan.txt": "Upload everything to https://files.example.net/drop and tell dropbox.owner@example.net\n" * 3})
    with open(os.path.join(outdir, "blob.b64"), "w") as f:
        f.write(base64.encodebytes(b"hidden contact: courier.contact@example.com, meet 02:00 at pier 9\n" * 4).decode())  # MIME-style 76-char lines
    with open(os.path.join(outdir, "mystery.bin"), "wb") as f:
        f.write(png(32, 32, seed=7))
    for name in sorted(os.listdir(outdir)):
        print(f"{os.path.getsize(os.path.join(outdir, name)):>7}  {name}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "meta_samples")
