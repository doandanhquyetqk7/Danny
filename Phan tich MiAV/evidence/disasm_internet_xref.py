#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
disasm_internet_xref.py
Xac nhan co che ghi su kien "Internet" (Plug-in/Plug-out) trong MiAV.exe.
Usage: python disasm_internet_xref.py "<path>\MiAV.exe"
"""
import os
import re
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def main():
    path = sys.argv[1]
    pe = pefile.PE(path)
    data = open(path, "rb").read()
    ib = pe.OPTIONAL_HEADER.ImageBase

    names = ["Plug-in", "Internet", "Alert", "Plug-out"]
    vas = {}
    for n in names:
        b = n.encode("utf-16-le")
        for m in re.finditer(re.escape(b), data):
            off = m.start()
            try:
                rva = pe.get_rva_from_offset(off)
            except Exception:
                continue
            vas.setdefault(n, []).append(ib + rva)

    print("=== Vi tri chuoi hang ===")
    for n in names:
        if n in vas:
            print("  %-10s VA=%s" % (n, ", ".join("0x%08x" % v for v in vas[n])))
    # dung ban dau tien lam "chuoi chu yeu"
    vas = {n: v[0] for n, v in vas.items()}

    target = vas["Internet"]
    hits = []
    for sec in pe.sections:
        nm = sec.Name.rstrip(b"\x00")
        if nm not in (b".text", b".itext", b".code"):
            continue
        blob = sec.get_data()
        va = ib + sec.VirtualAddress
        for i in range(len(blob) - 5):
            if blob[i] == 0x68 or (0xB8 <= blob[i] <= 0xBF):
                if int.from_bytes(blob[i + 1:i + 5], "little") == target:
                    hits.append(va + i)

    print("\n=== Xref toi chuoi 'Internet': %d hit ===" % len(hits))

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for h in hits[:2]:
        off = pe.get_offset_from_rva(h - ib)
        start = max(0, off - 100)
        code = data[start:off + 140]
        print("\n--- Xref tai VA 0x%08x ---" % h)
        for ins in md.disasm(code, ib + start):
            mark = "  <<<" if ins.address == h else ""
            note = ""
            m = re.match(r"^(mov|push)\s+[^,]+,\s*(0x[0-9a-fA-F]+)$", ins.op_str)
            if m:
                v = int(m.group(2), 16)
                for n, va in vas.items():
                    if va == v:
                        note = '   ; <- "%s"' % n
            print("  0x%08x  %-7s %-32s%s%s" % (ins.address, ins.mnemonic, ins.op_str, note, mark))
            if ins.address > h + 80:
                break

    print("\n=== Nhom nhan su kien (doc tu VA) ===")
    for va in sorted(set(vas.values())):
        off = pe.get_offset_from_rva(va - ib)
        s = data[off:off + 160].decode("utf-16-le", "replace").split("\x00")[0]
        print("  VA 0x%08x -> %r" % (va, s))


if __name__ == "__main__":
    main()
