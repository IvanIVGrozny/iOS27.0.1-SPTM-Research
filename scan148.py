from sptm import SPTM
import struct

s3 = SPTM("24B5099f/sptm.bin")
t = s3.text()

# decoders for load/store with arbitrary addressing
def decode_ls(w):
    """Return (kind, base, rt, byte_disp) or None."""
    rt = w & 0x1f
    rn = (w >> 5) & 0x1f
    # load/store register (unsigned immediate)
    if (w & 0x3b000000) == 0x39000000:
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        imm12 = (w >> 10) & 0xfff
        sz = 1 << size
        disp = imm12 * sz
        name = {1:'B',2:'H',4:'W',8:'X'}[sz]
        kind = ('LDR' if (opc & 1) == 1 else 'STR') + name
        return (kind, rn, rt, disp, 'uoff')
    # load/store register (post/pre-index, immediate)
    if (w & 0x3b200c00) == 0x38000c00:
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        imm9 = (w >> 12) & 0x1ff
        if imm9 & 0x100: imm9 -= 0x200
        mode = (w >> 10) & 3
        sz = 1 << size
        name = {1:'B',2:'H',4:'W',8:'X'}[sz]
        kind = ('LDR' if (opc & 1) == 1 else 'STR') + name
        tag = 'post' if mode == 1 else ('pre' if mode == 3 else 'unscaled')
        return (kind, rn, rt, imm9, tag)
    return None

hits = []
for off in range(t['fileoff'], t['fileoff'] + t['filesize'] - 8, 4):
    w = struct.unpack_from("<I", s3.d, off)[0]
    r = decode_ls(w)
    if not r:
        continue
    kind, rn, rt, disp, tag = r
    if disp == 0x148:
        hits.append((t['vmaddr'] + (off - t['fileoff']), kind, rn, rt, tag))

print("[xN + 0x148] accesses (all addressing forms):")
for h in hits:
    print("   %#x %-6s base=x%-2d rt=x%-2d (%s)" % h)
