#!/usr/bin/env python3
"""dec.py — decompress Apple LZFSE ('bvx2') im4p payloads via libcompression."""
import ctypes, sys

SZ = ctypes.c_size_t
lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
lib.compression_decode_buffer.restype = SZ
lib.compression_decode_buffer.argtypes = [
    ctypes.c_void_p, SZ, ctypes.c_void_p, SZ, ctypes.c_void_p, ctypes.c_int]

ALGOS = {'lzfse': 0x801, 'lz4': 0x800, 'lzvn': 0x802}


def decode(data, algo=0x801, cap=256 << 20):
    src = ctypes.create_string_buffer(bytes(data), len(data))
    out = ctypes.create_string_buffer(cap)
    n = lib.compression_decode_buffer(out, cap, src, len(data), None, algo)
    if not n:
        raise RuntimeError("decode failed")
    return out.raw[:n]


def unwrap_im4p(path):
    d = open(path, 'rb').read()
    start = d.find(b'bvx2')
    if start < 0:
        raise RuntimeError("no bvx2 stream")
    end = d.find(b'bvx$', start)
    end = end + 4 if end > 0 else len(d)
    return d[start:end]


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("usage: dec.py <im4p> <out.bin>")
        raise SystemExit(2)
    raw = unwrap_im4p(sys.argv[1])
    out = decode(raw)
    open(sys.argv[2], 'wb').write(out)
    print("%s -> %s (%d bytes)" % (sys.argv[1], sys.argv[2], len(out)))
    print("head:", out[:32].hex())
