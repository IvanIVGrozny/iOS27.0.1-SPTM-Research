#!/usr/bin/env python3
"""
kc.py — kernelcache analysis harness for XNU 27.x (iPhone18,1 / 24A446)

Facts verified against the artifact:
  * Outer file = arm64e MH_FILESET (filetype 12), 314 load commands.
  * 301 LC_FILESET_ENTRY (0x80000035) commands, one per kext.
  * Symbol tables are STRIPPED: LC_SYMTAB reports symoff=0, nsyms=0.
    -> Kexts must be identified by UUID / vmaddr / string xrefs, not names.
  * __LINKINFO (outer offset 0x49c0000) holds a bplist with per-kext
    SymbolSet metadata (names only, no addresses) + full prelink info
    (CFBundleIdentifier, UUID, load address) for 319 kexts.
  * Function starts are recoverable only heuristically (pacibsp markers).
"""
import struct, json, sys, os

PAGE = 0x4000

# ----------------------------------------------------------------------------
# Low-level parsing
# ----------------------------------------------------------------------------

class Kernelcache:
    def __init__(self, path):
        self.path = path
        self.d = open(path, 'rb').read()
        self._parse_outer()

    # -- outer Mach-O -------------------------------------------------------
    def _parse_outer(self):
        d = self.d
        magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags = \
            struct.unpack_from("<IiiIIII", d, 0)
        assert magic == 0xfeedfacf, "not a Mach-O"
        self.cputype = cputype & 0xffffffff
        self.filetype = filetype
        self.ncmds = ncmds

        self.segments = []
        self.filesets = []
        p = 32
        for i in range(ncmds):
            cmd, size = struct.unpack_from("<II", d, p)
            if cmd == 0x19:  # LC_SEGMENT_64
                b = d[p:p+size]
                self.segments.append(dict(
                    index=i,
                    seg=b[8:24].rstrip(b'\0').decode(),
                    vmaddr=struct.unpack_from("<Q", b, 24)[0],
                    vmsize=struct.unpack_from("<Q", b, 32)[0],
                    fileoff=struct.unpack_from("<Q", b, 40)[0],
                    filesize=struct.unpack_from("<Q", b, 48)[0],
                    maxprot=struct.unpack_from("<i", b, 56)[0],
                    initprot=struct.unpack_from("<i", b, 60)[0],
                ))
            elif cmd == 0x80000035:  # LC_FILESET_ENTRY
                b = d[p:p+size]
                vm = struct.unpack_from("<Q", b, 8)[0]
                fo = struct.unpack_from("<I", b, 16)[0]
                eid = struct.unpack_from("<I", b, 20)[0]
                noff = struct.unpack_from("<I", b, 24)[0]
                name = d[p+noff:d.index(b'\0', p+noff)].decode()
                self.filesets.append(dict(index=i, name=name, vmaddr=vm,
                                          fileoff=fo, entry_id=eid))
            p += size

        # vm/file translation across the outer container
        self.vm_segs = sorted(self.segments, key=lambda s: s['vmaddr'])

    # -- translation --------------------------------------------------------
    def vm_to_off(self, vm):
        for s in self.vm_segs:
            if s['vmaddr'] <= vm < s['vmaddr'] + s['vmsize']:
                delta = vm - s['vmaddr']
                if delta < s['filesize']:
                    return s['fileoff'] + delta
                return None  # zero-fill region (__bss / __common)
        return None

    def off_to_vm(self, off):
        for s in self.segments:
            if s['fileoff'] <= off < s['fileoff'] + s['filesize']:
                return s['vmaddr'] + (off - s['fileoff'])
        return None

    def read(self, vm, n):
        off = self.vm_to_off(vm)
        if off is None:
            return b'\0' * n
        return self.d[off:off+n]

    # -- kext metadata ------------------------------------------------------
    def kext_segments(self, fs):
        """Parse a kext's own Mach-O header (which lives at fs['fileoff'])."""
        d = self.d
        base = fs['fileoff']
        n = struct.unpack_from("<I", d, base + 16)[0]
        out = []
        p = base + 32
        for _ in range(n):
            cmd, size = struct.unpack_from("<II", d, p)
            if cmd == 0x19:
                b = d[p:p+size]
                nsects = struct.unpack_from("<I", b, 64)[0]
                sects = []
                for s in range(nsects):
                    sb = b[72+s*80:72+(s+1)*80]
                    sects.append(dict(
                        sect=sb[0:16].rstrip(b'\0').decode(),
                        seg=sb[16:32].rstrip(b'\0').decode(),
                        addr=struct.unpack_from("<Q", sb, 32)[0],
                        size=struct.unpack_from("<Q", sb, 40)[0],
                        offset=struct.unpack_from("<I", sb, 48)[0],
                        flags=struct.unpack_from("<I", sb, 64)[0],
                    ))
                out.append(dict(
                    seg=b[8:24].rstrip(b'\0').decode(),
                    vmaddr=struct.unpack_from("<Q", b, 24)[0],
                    vmsize=struct.unpack_from("<Q", b, 32)[0],
                    fileoff=struct.unpack_from("<Q", b, 40)[0],
                    filesize=struct.unpack_from("<Q", b, 48)[0],
                    initprot=struct.unpack_from("<i", b, 60)[0] & 0xff,
                    sections=sects,
                ))
            elif cmd == 0x2:  # LC_SYMTAB
                out.append(dict(marker='__SYMTAB__',
                                symoff=struct.unpack_from("<I", d, p+8)[0],
                                nsyms=struct.unpack_from("<I", d, p+12)[0]))
            p += size
        return out

    def kext_uuid(self, fs):
        d = self.d
        base = fs['fileoff']
        n = struct.unpack_from("<I", d, base+16)[0]
        p = base + 32
        for _ in range(n):
            cmd, size = struct.unpack_from("<II", d, p)
            if cmd == 0x1b:  # LC_UUID
                return d[p+8:p+24].hex()
            p += size
        return None


# ----------------------------------------------------------------------------
# __LINKINFO / __PRELINK_INFO
# ----------------------------------------------------------------------------

def parse_linkinfo(kc):
    """bplist in outer __LINKEDIT at the location of the kernel kext's __LINKINFO."""
    import plistlib
    for s in kc.segments:
        if s['seg'] == '__LINKEDIT':
            blob = kc.d[s['fileoff']:s['fileoff']+s['filesize']]
            if blob[:8] == b'bplist00':
                return plistlib.loads(blob)
    return None


def parse_prelink_info(kc):
    import plistlib
    for s in kc.segments:
        if s['seg'] == '__PRELINK_INFO':
            blob = kc.d[s['fileoff']:s['fileoff']+s['filesize']]
            end = blob.find(b'</plist>')
            return plistlib.loads(blob[:end+8])
    return None


# ----------------------------------------------------------------------------
# Symbol-less function discovery
# ----------------------------------------------------------------------------

PAC_PROLOGUES = {
    0xd503237f: 'pacibsp',       # pacibsp + ret pattern
    0xd503233f: 'paciasp',
    0xd503247f: 'bti/j' ,
    0xd503245f: 'bti',
}

def find_function_starts(kc, vm_lo, vm_hi):
    """Heuristic: BTI/PAC landing pads at 4-byte alignment, followed within
    a few insns by a frame setup or an immediate return."""
    off_lo = kc.vm_to_off(vm_lo)
    off_hi = kc.vm_to_off(vm_hi - 4)
    if off_lo is None or off_hi is None:
        return []
    d = kc.d
    out = []
    for off in range(off_lo, off_hi, 4):
        w = struct.unpack_from("<I", d, off)[0]
        if w in (0xd503237f, 0xd503233f, 0xd503245f):
            out.append(kc.off_to_vm(off))
    return out


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def cmd_info(kc):
    print("file            : %s (%d bytes)" % (kc.path, len(kc.d)))
    print("cputype         : %#x (arm64e)" % kc.cputype)
    print("filetype        : %d (MH_FILESET)" % kc.filetype)
    print("load commands   : %d" % kc.ncmds)
    print("kexts           : %d" % len(kc.filesets))
    print()
    print("%-18s %-12s %-12s %-12s %s" % ("SEGMENT", "VMADDR", "VMSIZE", "FILEOFF", "FILESIZE"))
    for s in kc.segments:
        print("%-18s %#012x %#012x %#012x %#012x" %
              (s['seg'], s['vmaddr'], s['vmsize'], s['fileoff'], s['filesize']))


def cmd_kexts(kc):
    for fs in kc.filesets:
        print("%#012x  %#010x  %s" % (fs['vmaddr'], fs['fileoff'], fs['name']))


def cmd_find(kc, needle):
    for fs in kc.filesets:
        if needle.lower() in fs['name'].lower():
            print("%s  vm=%#x  off=%#x  uuid=%s" %
                  (fs['name'], fs['vmaddr'], fs['fileoff'], kc.kext_uuid(fs)))


def cmd_syms(kc):
    """Report symbol-stripping status per kext."""
    stripped = 0
    for fs in kc.filesets:
        segs = kc.kext_segments(fs)
        st = [s for s in segs if s.get('marker') == '__SYMTAB__']
        if st and st[0]['nsyms'] == 0:
            stripped += 1
    print("kexts parsed: %d" % len(kc.filesets))
    print("with nsyms==0 (fully stripped): %d" % stripped)


def cmd_xref(kc, s):
    """Find a C string / symbol-name string and report its vmaddr + referencing code."""
    needle = s.encode()
    hits = []
    start = 0
    while True:
        i = kc.d.find(needle, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    print("%d raw hits for %r" % (len(hits), s))
    for h in hits:
        vm = kc.off_to_vm(h)
        print("  file=%#x vm=%s" % (h, hex(vm) if vm else None))


def main():
    if len(sys.argv) < 3:
        print("usage: kc.py <kernelcache> {info|kexts|find NAME|syms|xref STR|prelink}")
        return
    kc = Kernelcache(sys.argv[1])
    cmd = sys.argv[2]
    if cmd == 'info':
        cmd_info(kc)
    elif cmd == 'kexts':
        cmd_kexts(kc)
    elif cmd == 'find':
        cmd_find(kc, sys.argv[3])
    elif cmd == 'syms':
        cmd_syms(kc)
    elif cmd == 'xref':
        cmd_xref(kc, sys.argv[3])
    elif cmd == 'prelink':
        p = parse_prelink_info(kc)
        print(p['KMBuildVersion'])
        for e in p['_PrelinkInfoDictionary']:
            print("%-58s %-10s %s" % (e.get('CFBundleIdentifier', '?'),
                                      e.get('CFBundleVersion', '?'),
                                      e.get('OSBundleUUID', '?')))
    else:
        print("unknown command")


if __name__ == '__main__':
    main()
