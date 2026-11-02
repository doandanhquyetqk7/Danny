#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_miav_strings.py
Trich xuat chuoi ANSI + UTF-16 tu PE (co offset) - dung de grep phan tich tinh trang.
Usage: python extract_miav_strings.py <file.exe> <out.txt>
"""
import re
import sys

def main():
    src, out = sys.argv[1], sys.argv[2]
    data = open(src, "rb").read()

    rows = []  # (offset, encoding, text)

    # ANSI: >= 5 ky tu in duoc
    for m in re.finditer(rb"[\x20-\x7e]{5,}", data):
        rows.append((m.start(), "A", m.group().decode("ascii", "replace")))

    # UTF-16LE: >= 5 ky tu in duoc (ky tu ASCII + 0x00)
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){5,}", data):
        rows.append((m.start(), "W", m.group().decode("utf-16-le", "replace")))

    rows.sort(key=lambda r: r[0])

    with open(out, "w", encoding="utf-16") as f:
        for off, enc, txt in rows:
            f.write("0x%08x %s %s\n" % (off, enc, txt))

    print("%s -> %s  (%d strings)" % (src, out, len(rows)))

if __name__ == "__main__":
    main()
