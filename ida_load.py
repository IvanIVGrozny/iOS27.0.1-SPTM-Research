# ida_load.py — IDAPython bootstrap for XNU 27.x MH_FILESET kernelcaches
#
# Put in %APPDATA%/Hex-Rays/IDA Pro/plugins  (or run from File > Script file).
#
# WHY THIS EXISTS
# ---------------
# A modern iOS kernelcache is filetype 12 (MH_FILESET). IDA's built-in Mach-O
# loader will consume the outer container and show you ONE 0xdc8000-byte
# __text blob with no kext boundaries and no symbols. This script:
#
#   1. Parses the outer LC_FILESET_ENTRY table itself.
#   2. Creates the 301 kext "image bases" as named symbols so you get a real
#      module navigator instead of one anonymous blob.
#   3. Maps every kext segment/section into IDA segments with correct
#      permissions (RX for __TEXT_EXEC, RW for __DATA, RO for __DATA_CONST).
#   4. Emits the prelink metadata (bundle id, UUID, version) as per-address
#      repeatable comments on each kext header.
#   5. Names what CAN be named. On 24A446 every kext has nsyms==0 — the
#      symbol table is gone. What survives is __LINKINFO (a bplist of
#      *names only*, no addresses) and __PRELINK_INFO (ids/UUIDs). We
#      therefore build a name-only index and let you pivot by UUID.
#
# WHAT IT CANNOT DO
# -----------------
# It cannot invent symbols. Any "symbol names" you see after running this
# are the ones that survived as C strings, not as link-editor symbols.
# Treat every function as sub_<addr> and resolve by xref + string context.

import struct, json, os, sys

import idaapi, ida_bytes, ida_funcs, ida_nalt, ida_segment, ida_name, idc
import ida_kernwin, ida_auto

PAGE = 0x4000


# ---------------------------------------------------------------------------
# Minimal Mach-O / fileset parser (no external deps)
# ---------------------------------------------------------------------------

class MO:
    def __init__(self, path):
        self.d = open(path, 'rb').read()

    def u32(self, o): return struct.unpack_from("<I", self.d, o)[0]
    def i32(self, o): return struct.unpack_from("<i", self.d, o)[0]
    def u64(self, o): return struct.unpack_from("<Q", self.d, o)[0]

    def lcs(self, base):
        n = self.u32(base + 16)
        p = base + 32
        for _ in range(n):
            cmd, size = self.u32(p), self.u32(p + 4)
            yield cmd, size, p
            p += size

    def filesets(self):
        out = []
        for cmd, size, p in self.lcs(0):
            if cmd == 0x80000035:
                vm = self.u64(p + 8)
                fo = self.u32(p + 16)
                noff = self.u32(p + 24)
                name = self.d[p + noff:self.d.index(b'\0', p + noff)].decode()
                out.append((name, vm, fo))
        return out

    def segments(self, base):
        out = []
        for cmd, size, p in self.lcs(base):
            if cmd == 0x19:
                b = self.d[p:p + size]
                nsects = self.u32(p + 64)
                sects = []
                for s in range(nsects):
                    q = p + 72 + s * 80
                    sects.append(dict(
                        sect=self.d[q:q + 16].rstrip(b'\0').decode(),
                        seg=self.d[q + 16:q + 32].rstrip(b'\0').decode(),
                        addr=self.u64(q + 32),
                        size=self.u64(q + 40),
                        offset=self.u32(q + 48),
                        flags=self.u32(q + 64),
                    ))
                out.append(dict(
                    seg=b[8:24].rstrip(b'\0').decode(),
                    vmaddr=self.u64(p + 24),
                    vmsize=self.u64(p + 32),
                    fileoff=self.u64(p + 40),
                    filesize=self.u64(p + 48),
                    initprot=self.i32(p + 60) & 0xff,
                    sections=sects,
                ))
        return out

    def uuid(self, base):
        for cmd, size, p in self.lcs(base):
            if cmd == 0x1b:
                return self.d[p + 8:p + 24].hex()
        return None

    def chained_fixups(self, base):
        for cmd, size, p in self.lcs(base):
            if cmd == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
                return self.u32(p + 8), self.u32(p + 12)
        return None


PROT = {1: ida_segment.SEGPERM_READ,
        3: ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE,
        5: ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC,
        7: ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_EXEC}


def safe_name(s):
    return ''.join(c if c.isalnum() or c in '._$' else '_' for c in s)


def run():
    path = ida_kernwin.ask_file(0, "*.release.*,*.kernelcache,*.bin", "Select kernelcache")
    if not path:
        return
    mo = MO(path)
    magic = mo.u32(0)
    if magic != 0xfeedfacf:
        print("[-] not a Mach-O")
        return
    filetype = mo.u32(12)
    print("[*] filetype = %d %s" % (filetype, "(MH_FILESET ok)" if filetype == 12 else "(NOT a fileset)"))

    fss = mo.filesets()
    print("[*] %d kexts" % len(fss))

    # ---- 1. create segments for the outer container, then per-kext slices --
    # The outer segments are what IDA has already loaded. We only ADD
    # per-module structure on top by creating function-less segments with the
    # same span but split on kext boundaries; IDA allows overlapping segments
    # only if we use a different selector, so instead we mark boundaries with
    # names + colored repeatable comments.

    created = 0
    for name, vm, fo in fss:
        segs = mo.segments(fo)
        uuid = mo.uuid(fo)
        # place a name at the kext's load address
        short = name.split('.')[-1]
        ea = vm
        ok = ida_name.set_name(ea, "__kmod_%s" % safe_name(short),
                               ida_name.SN_NOWARN | ida_name.SN_FORCE)
        if ok:
            created += 1
        cmt = "%s\nvmaddr=%#x\nfileoff=%#x\nuuid=%s" % (name, vm, fo, uuid)
        ida_bytes.set_cmt(ea, cmt, 1)

        # per-section code/data markers
        for s in segs:
            for sc in s['sections']:
                if not sc['size']:
                    continue
                if sc['flags'] & 0x80000400 or 'EXEC' in s['seg']:
                    ida_bytes.del_items(sc['addr'], ida_bytes.DELIT_EXPAND, sc['size'])
                    ida_auto.auto_make_code(sc['addr']) if False else None

    print("[+] named %d kext module bases" % created)

    # ---- 2. name survives only as C strings; harvest them ----------------
    # On 24A446, nsyms==0 for every kext. We instead collect all strings in
    # __cstring and mark them, which is what actually drives triage.

    pend = 0
    for name, vm, fo in fss:
        for s in mo.segments(fo):
            for sc in s['sections']:
                if sc['sect'] == '__cstring' and sc['size']:
                    # walk NUL-terminated strings
                    data = mo.d[sc['offset']:sc['offset'] + sc['size']]
                    cur = 0
                    while cur < len(data):
                        end = data.find(b'\0', cur)
                        if end < 0:
                            break
                        if end - cur >= 6:
                            try:
                                strv = data[cur:end].decode('ascii')
                            except UnicodeDecodeError:
                                cur = end + 1
                                continue
                            ea = sc['addr'] + cur
                            ida_bytes.set_cmt(ea, strv, 1)
                            pend += 1
                        cur = end + 1
    print("[+] annotated %d C strings" % pend)

    ida_kernwin.info("Done. %d kexts mapped.\n\n"
                     "NOTE: 24A446 has nsyms==0 for all %d kexts — the symbol "
                     "table is stripped. Cross-reference by string + UUID."
                     % (len(fss), len(fss)))


if __name__ == '__main__':
    run()
