from sptm import SPTM
import struct

DISP = 0x91   # corrected gate-byte offset inside per-CPU SPTM state

s3 = SPTM("24B5099f/sptm.bin")
t = s3.text()

def decode_ls(w):
    rt = w & 0x1f
    rn = (w >> 5) & 0x1f
    if (w & 0x3b000000) == 0x39000000:          # unsigned offset
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        disp = ((w >> 10) & 0xfff) * (1 << size)
        return (('LDR' if opc & 1 else 'STR') + 'BHXW'[size], rn, rt, disp, 'uoff')
    if (w & 0x3b200c00) == 0x38000c00:          # post/pre/unscaled
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        imm9 = (w >> 12) & 0x1ff
        if imm9 & 0x100:
            imm9 -= 0x200
        mode = (w >> 10) & 3
        return (('LDR' if opc & 1 else 'STR') + 'BHXW'[size], rn, rt, imm9,
                {1: 'post', 3: 'pre'}.get(mode, 'unscaled'))
    return None

hits = []
for off in range(t['fileoff'], t['fileoff'] + t['filesize'] - 8, 4):
    w = struct.unpack_from("<I", s3.d, off)[0]
    r = decode_ls(w)
    if not r:
        continue
    kind, rn, rt, disp, tag = r
    if disp == DISP:
        hits.append((t['vmaddr'] + (off - t['fileoff']), kind, rn, rt, tag))

print("[xN + %#x] accesses across __TEXT_EXEC:" % DISP)
for h in hits:
    print("   %#x %-6s base=x%-2d rt=x%-2d (%s)" % h)
