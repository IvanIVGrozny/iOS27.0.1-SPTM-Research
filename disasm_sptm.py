#!/usr/bin/env python3
"""disasm_sptm.py — minimal AArch64 disassembler (subset used by SPTM/XNU)."""
def sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v

def dec_adrp(w, pc):
    imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
    return (pc & ~0xfff) + (sx(imm, 21) << 12)

def dis(w, pc):
    X = lambda n: "x%d" % n
    W = lambda n: "w%d" % n
    if w == 0xd503237f: return "pacibsp"
    if w == 0xd503233f: return "paciasp"
    if w == 0xd503245f: return "bti"
    if w == 0xd503201f: return "nop"
    if w == 0xd65f03c0: return "ret"
    if w == 0xd65f0fff: return "retab"
    if (w & 0x9f000000) == 0x90000000:
        return "adrp %s, %#x" % (X(w & 0x1f), dec_adrp(w, pc))
    if (w & 0xff800000) == 0x91000000:
        return "add %s, %s, #%#x" % (X(w & 0x1f), X((w >> 5) & 0x1f), (w >> 10) & 0xfff)
    if (w & 0xff800000) == 0xd1000000:
        return "sub %s, %s, #%#x" % (X(w & 0x1f), X((w >> 5) & 0x1f), (w >> 10) & 0xfff)
    if (w & 0xffc00000) == 0xf9400000:
        return "ldr %s, [%s, #%#x]" % (X(w & 0x1f), X((w >> 5) & 0x1f), ((w >> 10) & 0xfff)*8)
    if (w & 0xffc00000) == 0xb9400000:
        return "ldr %s, [%s, #%#x]" % (W(w & 0x1f), X((w >> 5) & 0x1f), ((w >> 10) & 0xfff)*4)
    if (w & 0xffc00000) == 0xf9000000:
        return "str %s, [%s, #%#x]" % (X(w & 0x1f), X((w >> 5) & 0x1f), ((w >> 10) & 0xfff)*8)
    if (w & 0xffc00000) == 0xb9000000:
        return "str %s, [%s, #%#x]" % (W(w & 0x1f), X((w >> 5) & 0x1f), ((w >> 10) & 0xfff)*4)
    if (w & 0x7c000000) == 0x14000000:
        return "b %#x" % (pc + (sx(w & 0x3ffffff, 26) << 2))
    if (w & 0xfc000000) == 0x94000000:
        return "bl %#x" % (pc + (sx(w & 0x3ffffff, 26) << 2))
    if (w & 0xff000010) == 0x54000000:
        c = ["eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"][w & 0xf]
        return "b.%s %#x" % (c, pc + (sx((w >> 5) & 0x7ffff, 19) << 2))
    if (w & 0x7f800000) == 0x52800000:
        return "mov %s, #%#x" % (W(w & 0x1f), (w >> 5) & 0xffff)
    return ".word %#010x" % w
