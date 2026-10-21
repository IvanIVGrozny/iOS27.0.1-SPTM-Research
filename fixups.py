#!/usr/bin/env python3
"""
fixups.py — arm64e kernelcache chained-fixup decoder.

Kernelcaches built for arm64e use LC_DYLD_CHAINED_FIXUPS with the
arm64e kernel pointer format. Raw pointers on disk look like:

    0x8011000003b4c9ec
    ||||     +-- 32-bit offset from the image base (0xfffffe0007004000)
    |||+-------- 16-bit "diversity" / high8 field (0 for kernel)
    ||+--------- key: 0=IA 1=IB 2=DA 3=DB
    |+---------- next: 11-bit stride to the next fixup (x4 bytes), 0 = end
    +----------- auth: 1 = PAC-signed pointer

This module decodes them and can also APPLY base relocations to a byte range
so the constants IDA shows as garbage become real addresses.
"""
import struct

KERNEL_BASE = 0xfffffe0007004000

AUTH = 1 << 63
BIND = 1 << 62
NEXT_SHIFT = 51
NEXT_MASK = 0x7ff
KEY_SHIFT = 49
KEY_MASK = 0x3
DIV_SHIFT = 32
DIV_MASK = 0xffff
OFF_MASK = 0xffffffff

KEYS = {0: 'IA', 1: 'IB', 2: 'DA', 3: 'DB'}


def decode(raw, base=KERNEL_BASE):
    auth = (raw >> 63) & 1
    bind = (raw >> 62) & 1
    nxt = (raw >> NEXT_SHIFT) & NEXT_MASK
    key = (raw >> KEY_SHIFT) & KEY_MASK
    div = (raw >> DIV_SHIFT) & DIV_MASK
    off = raw & OFF_MASK

    if auth:
        target = base + off
        kind = 'auth'
    else:
        # unauth kernel pointers: sign-extend the 32-bit offset from base
        target = base + (off if off < 0x80000000 else off - 0x100000000)
        kind = 'plain'

    return dict(auth=auth, bind=bind, next=nxt, key=KEYS[key],
                diversity=div, target=target, kind=kind)


def walk(blob, start=0, base=KERNEL_BASE):
    """Walk a chained-fixup chain starting at a byte offset into blob."""
    out = []
    i = start
    while 0 <= i < len(blob) - 8:
        raw = struct.unpack_from("<Q", blob, i)[0]
        info = decode(raw, base)
        info['offset'] = i
        out.append(info)
        if info['bind']:
            break                     # bind records store an ordinal, not an addr
        if info['next'] == 0:
            break
        i += info['next'] * 4
        if len(out) > 100000:
            break
    return out


def rebase_range(blob, base=KERNEL_BASE):
    """Return a list of (offset, raw, decoded) for every plausible fixup slot."""
    out = []
    for i in range(0, len(blob) - 8, 8):
        raw = struct.unpack_from("<Q", blob, i)[0]
        if raw == 0:
            continue
        if (raw >> 63) and ((raw >> 49) & 3) in KEYS:
            info = decode(raw, base)
            if KERNEL_BASE <= info['target'] < 0xfffffe000ba20000:
                out.append((i, raw, info))
    return out


if __name__ == '__main__':
    import sys
    from kc import Kernelcache
    kc = Kernelcache(sys.argv[1])
    seg = sys.argv[2] if len(sys.argv) > 2 else '__DATA_CONST'
    s = [x for x in kc.segments if x['seg'] == seg][0]
    blob = kc.d[s['fileoff']:s['fileoff'] + s['filesize']]
    fx = rebase_range(blob)
    print("%s: %d fixups in %d bytes" % (seg, len(fx), len(blob)))
    for i, raw, info in fx[:20]:
        print("  +%#08x  %016x -> %#x  key=%s div=%#x nxt=%d" %
              (i, raw, info['target'], info['key'], info['diversity'], info['next']))
