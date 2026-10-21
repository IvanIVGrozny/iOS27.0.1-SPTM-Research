#!/usr/bin/env python3
"""fdiff.py — canonical function diff between two SPTM builds.

adrp page immediates and branch targets shift with relocation, so a raw byte
diff is useless. This normalises:
  - adrp  -> ADRP rd      (immediate dropped, page recorded separately)
  - bl/b  -> BRANCH       (target resolved to a symbol name if known)
  - b.cond/cbz -> BCOND   (offset dropped)
  - ldr/str offsets kept (they are structural)
"""
import struct, sys
from sptm import SPTM

def canon(s, start, length):
    o = s.vm2off(start)
    out = []
    for i in range(0, length, 4):
        if o + i + 4 > len(s.d):
            break
        w = int.from_bytes(s.d[o+i:o+i+4], 'little')
        pc = start + i
        if (w & 0x9f000000) == 0x90000000:
            imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
            if imm & (1 << 20):
                imm -= (1 << 21)
            page = (pc & ~0xfff) + (imm << 12)
            out.append(("ADRP", w & 0x1f, page))
        elif (w & 0xfc000000) == 0x94000000:
            tgt = pc + (((w & 0x3ffffff) - (1 << 26) if w & (1 << 25) else (w & 0x3ffffff)) << 2)
            out.append(("BL", tgt))
        elif (w & 0x7c000000) == 0x14000000:
            tgt = pc + (((w & 0x3ffffff) - (1 << 26) if w & (1 << 25) else (w & 0x3ffffff)) << 2)
            out.append(("B", tgt))
        elif (w & 0xff000010) == 0x54000000:
            out.append(("BCOND", w & 0xf))
        elif (w & 0x7e000000) == 0x34000000:
            out.append(("CBZ", w))
        else:
            out.append(("RAW", w))
    return out


def diff(s1, a, s3, b, length):
    A = canon(s1, a, length)
    B = canon(s3, b, length)
    print("b1 %#x  (%d insns)" % (a, len(A)))
    print("b3 %#x  (%d insns)" % (b, len(B)))
    print()
    n = max(len(A), len(B))
    shown = 0
    for i in range(n):
        x = A[i] if i < len(A) else None
        y = B[i] if i < len(B) else None
        if x is None or y is None or x[0] != y[0] or (
                x[0] == "RAW" and x[1] != y[1]) or (
                x[0] == "BCOND" and x[1] != y[1]) or (
                x[0] == "CBZ" and x[1] != y[1]) or (
                x[0] == "ADRP" and x[1] != y[1]) or (
                x[0] == "BL" and False):
            xs = str(x) if x else "-"
            ys = str(y) if y else "-"
            if x and y and x[0] == "BL":
                continue            # call target differs by relocation; skip
            if x and y and x[0] == "ADRP":
                continue
            print("  @%#06x  b1=%-22s b3=%s" % (i*4, xs, ys))
            shown += 1
            if shown > 60:
                print("  ...")
                break


if __name__ == '__main__':
    if len(sys.argv) < 6:
        print("usage: fdiff.py <b1.bin> <b3.bin> <b1_addr> <b3_addr> <length>")
        raise SystemExit(2)
    s1 = SPTM(sys.argv[1]); s3 = SPTM(sys.argv[2])
    a = int(sys.argv[3], 16); b = int(sys.argv[4], 16); ln = int(sys.argv[5], 16)
    diff(s1, a, s3, b, ln)
