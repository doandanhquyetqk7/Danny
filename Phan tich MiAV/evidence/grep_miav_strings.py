#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
grep_miav_strings.py
Grep nhieu mau (regex) trong file chuoi PE da trich, tu dong nhan dien encoding.
Usage: python grep_miav_strings.py <strings.txt> <mau1> [mau2 ...]
"""
import re
import sys


def load(path):
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        enc = "utf-16"
    elif raw[:3] == b"\xef\xbb\xbf":
        enc = "utf-8-sig"
    else:
        enc = "utf-8"
    return raw.decode(enc, "replace").split("\n")


def main():
    path = sys.argv[1]
    lines = load(path)
    for p in sys.argv[2:]:
        try:
            rx = re.compile(p, re.I)
        except re.error:
            rx = re.compile(re.escape(p), re.I)
        hits = [(i + 1, l) for i, l in enumerate(lines) if rx.search(l)]
        print("### %-45s -> %d hit" % (p, len(hits)))
        for n, l in hits[:40]:
            print("  %6d| %s" % (n, l[:220]))
        print()


if __name__ == "__main__":
    main()
