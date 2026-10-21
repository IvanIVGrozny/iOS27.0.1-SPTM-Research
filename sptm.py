#!/usr/bin/env python3
"""sptm.py — parser + xref tools for decompressed SPTM Mach-O binaries."""
import struct

class SPTM:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        self.segs = self._layout()

    def _layout(self):
        d = self.d
        n = struct.unpack_from("<I", d, 16)[0]
        p = 32; out = []
        for _ in range(n):
            cmd, size = struct.unpack_from("<II", d, p)
            if cmd == 0x19:
                b = d[p:p+size]
                out.append(dict(fileoff=struct.unpack_from("<Q", b, 40)[0],
                                vmaddr=struct.unpack_from("<Q", b, 24)[0],
                                filesize=struct.unpack_from("<Q", b, 48)[0],
                                name=b[8:24].rstrip(b'\0').decode()))
            p += size
        return out

    def vm2off(self, vm):
        for s in self.segs:
            if s['vmaddr'] <= vm < s['vmaddr'] + s['filesize']:
                return s['fileoff'] + (vm - s['vmaddr'])
        return None

    def off2vm(self, off):
        for s in self.segs:
            if s['fileoff'] <= off < s['fileoff'] + s['filesize']:
                return s['vmaddr'] + (off - s['fileoff'])
        return None

    def text(self):
        return [s for s in self.segs if s['name'] == '__TEXT_EXEC'][0]

    def xrefs(self, target):
        """adrp+add / adrp+ldr references to a VM address."""
        t = self.text()
        out = []
        for off in range(t['fileoff'], t['fileoff'] + t['filesize'] - 16, 4):
            w = struct.unpack_from("<I", self.d, off)[0]
            if (w & 0x9f000000) != 0x90000000:
                continue
            imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
            if imm & (1 << 20):
                imm -= (1 << 21)
            pc = t['vmaddr'] + (off - t['fileoff'])
            page = (pc & ~0xfff) + (imm << 12)
            for k in (1, 2):
                w2 = struct.unpack_from("<I", self.d, off + 4*k)[0]
                if (w2 & 0xff800000) == 0x91000000:
                    if page + ((w2 >> 10) & 0xfff) == target:
                        out.append(pc)
                elif (w2 & 0xffc00000) == 0xf9400000:
                    if page + ((w2 >> 10) & 0xfff)*8 == target:
                        out.append(pc)
        return out

    def string_at(self, vm, maxlen=160):
        o = self.vm2off(vm)
        if o is None:
            return None
        e = self.d.find(b'\0', o)
        if e < 0 or e - o > maxlen:
            return None
        try:
            s = self.d[o:e].decode('ascii')
        except UnicodeDecodeError:
            return None
        return s if len(s) >= 4 else None

    def find_str(self, needle):
        i = self.d.find(needle.encode() if isinstance(needle, str) else needle)
        return None if i < 0 else self.off2vm(i)

    def func_start(self, vm, maxback=0x4000):
        o = self.vm2off(vm)
        for back in range(0, maxback, 4):
            w = struct.unpack_from("<I", self.d, o - back)[0]
            if w in (0xd503237f, 0xd503233f):
                return vm - back
        return None

    def disasm(self, vm, count):
        from disasm_sptm import dis
        o = self.vm2off(vm)
        for i in range(count):
            w = struct.unpack_from("<I", self.d, o + i*4)[0]
            print("  %#x %08x  %s" % (vm + i*4, w, dis(w, vm + i*4)))
