#!/usr/bin/env python3
"""mail_hops.py - summarise an email's routing and authentication headers, oldest hop first.

Usage: mail_hops.py MESSAGE.eml [MESSAGE2.eml ...]

For each message it prints:
  - the identity headers (From, Reply-To, Return-Path, Message-ID, Date as written and in UTC)
  - the Received chain read bottom-up (hop 1 = the oldest, added first, nearest the sender), with each
    hop's time in UTC and the delay since the previous hop. Only the hops added by servers you trust
    (your own and your provider's) are reliable: a sender can write fake Received lines below them.
  - the receiving server's verdicts from Authentication-Results (SPF, DKIM, DMARC) and the domains
    they were checked against, and whether those domains match the From domain's registered domain
    (DMARC alignment; "registered domain" is approximated here as the last two labels, which is
    wrong for domains such as example.co.uk).
Standard library only; it only reads the file.
"""
import datetime
import email
import email.policy
import email.utils
import re
import sys


def one_line(value):
    return " ".join(str(value).split()) if value is not None else "-"


def base(dom):
    return ".".join(dom.split(".")[-2:]) if dom != "-" else "-"


def utc(text):
    try:
        return email.utils.parsedate_to_datetime(text.strip())
    except (TypeError, ValueError, IndexError):
        return None


def host(part):
    """'mta39.email2.microsoft.com (136.147.186.39)' -> 'mta39.email2.microsoft.com [136.147.186.39]'."""
    name = part.split()[0] if part.split() else "-"
    ip = re.search(r"[\[(]((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]*:[0-9a-f:]+)[\])]", part, re.I)
    return f"{name[:40]} [{ip.group(1)}]" if ip else name[:40]


def hop(received):
    text = one_line(received)
    stamp = utc(text.rpartition(";")[2]) if ";" in text else None
    m_from = re.match(r"from\s+(.*?)(?=\s+by\s|$)", text)        # "by X ... (envelope-from <...>)" has no sender
    m_by = re.search(r"(?:^|\s)by\s+(\S+)", text)
    return (host(m_from.group(1)) if m_from else "-"), (m_by.group(1) if m_by else "-"), stamp


def show(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.compat32)
    print(f"== {path}")
    print(f"Subject:     {one_line(msg.get('Subject'))[:70]}")
    for name in ("From", "Reply-To", "Return-Path"):
        print(f"{name + ':':<12} {one_line(msg.get(name))[:70]}")
    print(f"Message-ID:  {one_line(msg.get('Message-ID'))[:70]}")
    date = utc(one_line(msg.get("Date")))
    print(f"Date:        {one_line(msg.get('Date'))}  =  {date.astimezone(datetime.timezone.utc):%Y-%m-%d %H:%M:%S} UTC"
          if date else f"Date:        {one_line(msg.get('Date'))}")

    hops = [hop(r) for r in reversed(msg.get_all("Received") or [])]
    print(f"Received:    {len(hops)} hop(s), oldest first" if hops else "Received:    none (created inside the mailbox system)")
    prev = None
    for i, (frm, by, stamp) in enumerate(hops, 1):
        when = f"{stamp.astimezone(datetime.timezone.utc):%Y-%m-%d %H:%M:%S}" if stamp else "?" * 19
        delay = f"+{int((stamp - prev).total_seconds())}s" if stamp and prev else ""
        print(f"  {i}  {when}  {delay:>4}  from {frm}")
        print(f"     {'':19}  {'':>4}  by   {by}")
        prev = stamp or prev

    ar = one_line(msg.get("Authentication-Results"))
    if ar != "-":
        get = lambda key: (re.search(rf"\b{key}=([^\s;()]+)", ar) or [None, "-"])[1]
        from_dom = get(r"header\.from").lower()
        mailfrom, dkim_d = get(r"smtp\.mailfrom").rpartition("@")[2].lower(), get(r"header\.d").lower()
        print(f"Auth:        spf={get('spf')} dkim={get('dkim')} dmarc={get('dmarc')} (DMARC checked the From domain {from_dom})")
        print(f"  SPF domain  {mailfrom:<28} aligned with {from_dom}: {'yes' if base(mailfrom) == base(from_dom) else 'no'}")
        print(f"  DKIM domain {dkim_d:<28} aligned with {from_dom}: {'yes' if base(dkim_d) == base(from_dom) else 'no'}")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for p in sys.argv[1:]:
        show(p)
