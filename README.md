# Anatomy of an SPTM TLB-Invalidation Race Fix

### iOS 27.2 beta 1 → beta 3, iPhone18,4 (T8150)

---

## Abstract

Between iOS 27.2 beta 1 (`24B5084k`) and beta 3 (`24B5099f`), Apple made a
substantial change to the Secure Page Table Monitor's address-translation
code. The change adds a per-CPU mutual-exclusion gate, a set of memory
barriers, and optional GMMU TLBI verification around every UAT stage-2
mapping mutation.

The pattern — a synchronisation protocol bolted onto translation-mutation
paths, with a new hardware-derived status check and a new "failed to verify
TLBI" panic — is the signature of a **concurrent TLB-invalidation race** being
closed rather than a logic bug being patched.

This document characterises the fix. It does not present a working exploit.

---

## 1. Corpus and method

| Build | Kernelcache | SPTM |
|---|---|---|
| 27.0.1 | `24A446` | `SPTM-820.40.18` |
| 27.2b1 | `24B5084k` | `SPTM-820.40.18` |
| 27.2b3 | `24B5099f` | `SPTM-820.40.23` |

**Key observation:** 27.0.1 and 27.2b1 ship a *byte-identical* SPTM image.
The entire SPTM delta of this period is b1 → b3. Any analysis that only
compares 27.0.1 to a beta will attribute two releases' worth of change to one.

Both images are fully symbol-stripped (`nsyms == 0` in every kext, and the
SPTM Mach-O carries no symtab). All identification below is by structure,
string reference, and call-graph shape.

**Extraction:** `Firmware/sptm.t8150.release.im4p` is an ASN.1 `IM4P` envelope
wrapping a single LZFSE (`bvx2`) stream that decodes to a raw arm64e
`MH_EXECUTE` Mach-O. `dec.py` in this directory reproduces it.

---

## 2. Scale of the change

| | b1 | b3 | delta |
|---|---|---|---|
| SPTM `__text` | `0x61340` | `0x62038` | **+3,320 B** |
| `dmb ish` | 3 | **27** | **+24** |
| `dmb ishld` | 11 | 11 | 0 |
| `hint #62` | 4 | 10 | +6 |
| reads of `S3_3_C14_C0_6` | 18 | **41** | +23 |
| reads of `S3_3_C14_C0_0` | 7 | 23 | +16 |

The barrier count is the single largest structural change. Twenty-four new
full barriers across 3,320 bytes of new code is an extremely high density and
immediately suggests an ordering fix rather than a feature.

---

## 3. The new surface

21 strings are added, 3 removed:

```
+ uat_sync_outer_tlb_sapt_flush
+ VIOLATION_T8110_DART_UNGANG_GAPF_RACE
+ uat_dekkerlock_lock / uat_dekker_gate_lock
+ verify-gmmu-tlbis-at-sync / gmmu-tlbis-at-retype
+ gmmu-tlbi-verification-reg / gmmu-tlbi-verification-bit
+ %s: Failed to verify TLBI
+ %s: The GMMU TLBI verification register should be 8B-aligned
+ %s: UAT Dekker {lock,gate} acquisition timed out after %llu ns (spun for %llu cycles)
+ %s: relaxed_rw_protections and allow_pte_remap are not supported together
- wrprot
```

Four of these are load-bearing:

- **`uat_sync_outer_tlb_sapt_flush`** — the entry point. Present in all five
  guarded functions, absent from every XNU build.
- **`VIOLATION_T8110_DART_UNGANG_GAPF_RACE`** — names a DART (Apple's IOMMU)
  race involving an *un-ganged* invalidation, i.e. splitting one entry out of
  a batched TLBI.
- **`uat_dekker*_lock`** — a Dekker-style mutual-exclusion protocol.
- **`arg`/`allow_pte_remap` refusal** — a PTE that can be remapped may no
  longer also have relaxed read/write protections.

---

## 4. The guarded functions

Five b3 functions reference the flush entry point. All have b1 twins,
matched by internal string anchors:

| b1 | b3 | function | b1 | b3 |
|---|---|---|---|---|
| `0x…0b7acc` | `0x…0c7acc` | `sptm_uat_remove_ctx_id` | 0x420 | 0x5c4 |
| `0x…0b847c` | `0x…0c8620` | `sapt_update_permissions_uat_unmap_sync` | 0x34c | 0x4f4 |
| `0x…0b95b0` | `0x…0c98fc` | `sptm_uat_prepare_fw_unmap_continue` | 0x34c | 0x4f0 |
| `0x…0b8100` | `0x…0c82a4` | `uat_state_get_root_table_paddr` | 0x37c | 0x37c |

The three *mutation* functions each grew ~0x1A8. The read-only accessor grew by
**exactly zero**. The guard is applied where translations change, not where
they are inspected — a precise, deliberate placement.

---

## 5. The gate

### Acquisition

```asm
  ldr  x10, [x8, #0x208]        ; per-CPU SPTM state
  ldrb w11, [x10, #0x91]!       ; gate byte at state+0x91
  tbnz w11, #0, .Lretry         ; held -> spin
  mov  w11, #0
  <ldxr/stxr CAS>
  cmp  w11, #0
  b.ne .Lretry
  mov  w13, #1
  strb w13, [x10, #0x10]        ; mark in-critical-section
  dmb  ish                      ; <-- the barrier b1 lacks
```

**Gate byte:** one byte at `per-CPU state + 0x91`, bit 0. There are exactly
five test sites (the five guarded functions) and exactly one clear site
(`0xfffffff0270cce0c`, `strb wzr,[x8,#0x91]`).

### Release

```asm
  ldr  x8, [x8, #0x208]
  strb wzr, [x8, #0x91]         ; clear gate
  strb wzr, [x0, #0x10]
  strb wzr, [x0, #0x11]
```

### Timing

The spin is bounded against an SPTM-private tick counter:

```asm
  mrs  x10, S3_3_C14_C0_6
  subs x10, x10, x0             ; x0 = deadline
  b.hi .Ltimeout
```

Deadline is `now + 0x30d40` = **200,000 ticks**. At a typical 24 MHz counter
rate that is **8.33 ms** — a millisecond-scale budget. Apple's spinlock
timeouts are normally hundreds of microseconds; 8 ms says the designers
expected the guarded section to be held for genuinely long periods.

The timeout panic reports `t / 10000`, computed with a
`ceil(2^65/10^4)` fixed-point multiplier (`0xd1b71758e2197`) — a Barrett-style
reciprocal for division by 10,000.

---

## 6. The peer is the GPU

The function containing the gate release (`0xfffffff0270cbecc`) references
**209 strings**, including:

```
/arm-io/sgx                       agx-address-space-mgmt-mode
issue-gmmu-tlbis-at-retype        gfx-shared-region-base
verify-gmmu-tlbis-at-sync         gfx-shared-l2-region-base
gmmu-tlbi-verification-reg        gpu-region-base / size
gmmu-tlbi-verification-bit        gfx-handoff-base / size
/arm-io/sapt                      uat_bootstrap_parse_dt
```

`agx-` is Apple's GPU driver prefix; `sgx` is the GPU device-tree node; `gmmu`
is the GPU Memory Management Unit.

**The gate serialises SPTM against the GPU's GMMU TLBI engine.** It is not
another CPU in SPTM — b1 contains zero occurrences of `uat_dekker` anywhere.

---

## 7. The supporting machinery

### `S3_3_C4_C2_1` — a check-then-barrier status register

Encoding `op0=3, op1=3, CRn=4, CRm=2, op2=1` — unallocated by ARM.

Usage census across the whole image:

| property | count |
|---|---|
| reads masked with `TST`/`ANDS` logical-immediate | **16 / 18** |
| reads compared (`CMP`) against an immediate | **0** |
| poll loops on the value | **0** |

The mask is universally `0x1c0` (bits 8–6). The idiom:

```asm
mrs  xN, S3_3_C4_C2_1
tst  xM, #0x1c0
b.eq 1f
hint #62                ; implementation-defined synchronisation hint
1:  yield ; ... mrs S3_3_C14_C0_6 ...
```

Zero comparisons rules out counter semantics — a timeout loop cannot exist
without a comparison. Zero poll loops rules out "wait for hardware quiesce" —
nothing waits for the value to change. The software reads it, converts
"nonzero" into a barrier, and proceeds.

It is also conditionally written back (`mrs`/`msr` around the mask test), with
the `== 0x40` case (i.e. `0b010` in the field) specifically skipping the
write-back. The software-visible granularity is therefore three classes:
zero, `0x40`, and any other nonzero.

Every site that reads it is in the translation-mutation cluster —
`sptm_broadcast_tlbi`, `frame_release`, `release_shared_root_pt`,
`sapt_update_permissions_uat_unmap_sync`.

### `S3_3_C14_C0_6` — SPTM tick counter

Encoding `op0=3, op1=3, CRn=14, CRm=0, op2=6` — the generic-timer encoding
neighbourhood, with `op2=6` unallocated.

It **pre-existed** in b1 (18 reads), paired with `S3_3_C14_C0_0` (`CNTFRQ_EL0`
by encoding) and an `madd` to convert ticks → nanoseconds. It is a
firmware-maintained monotonic tick counter and its frequency, mirroring
`CNTPCT_EL0`/`CNTFRQ_EL0`.

The infrastructure for bounded waits existed long before this fix. Only the
gate's use of it is new.

### GMMU TLBI verification

`verify-gmmu-tlbis-at-sync` and `gmmu-tlbis-at-retype` are device-tree/boot
properties. A third string —
`verify-gmmu-tlbis-at-sync is enabled but gmmu-tlbi-verification-reg is not set`
— makes the dependency explicit.

**Verification is opt-in.** `Failed to verify TLBI` is therefore a
debug/engineering panic, not a shipping-user crash. This is consistent with a
researcher observing it on a device provisioned with the boot property set.

---

## 8. What the fix implies about the bug

The guarded region in b1, before the fix:

```
  write PTE
  --------------------- <-- GPU GMMU TLBI can complete here
  issue TLBI (uat_sync_outer_tlb_sapt_flush)
```

The page-table write is not ordered with respect to the TLBI issue, and
neither is serialised against the GPU's concurrent invalidation engine. If the
GMMU completes an invalidation for an overlapping range between the two, the
GPU retains a translation the page table no longer describes.

b3 addresses this on three axes:

1. **Ordering** — `dmb ish` between the acquire and the critical section, and
   again at release. 24 new full barriers.
2. **Exclusion** — a per-CPU gate so the GMMU cannot operate inside the window.
3. **Verification** — an optional register/bit pair so a TLBI can be confirmed
   rather than assumed.

The 8 ms spin budget is indirect evidence that the window is not a
two-instruction sliver: the designers budgeted for a long hold.

---

## 9. Why this is hard to patchdiff

- The fix is **not one check**. It is a lock protocol inlined across three
  large functions, plus a bootstrap parser change, plus a status-register
  protocol, plus an optional verification path.
- The guard is **interleaved** with existing code — a naive function-level
  patchdiff shows a 424-byte insertion in three places with no clean boundary.
- It depends on **undocumented SPTM-private registers** (`S3_3_C4_C2_1`,
  `S3_3_C14_C0_6`, `hint #62`). Reimplementing the behaviour requires
  reverse-engineering what those do, which the encoding does not reveal.
- The bug is **timing-dependent**. "Did I reproduce it" is not decidable by
  inspection, and a fix cannot be validated by reading.

The barrier census (`dmb ish`: 3 → 27) is probably the fastest route to
locating it for anyone doing this independently.

---

## 10. Open questions

| question | status |
|---|---|
| What are the three software-visible states of `S3_3_C4_C2_1[8:6]`? | device question |
| What does `hint #62` do architecturally? | undocumented |
| Which second party does the Dekker gate name? | GPU GMMU (inferred from string cluster) |
| Is verification enabled on production devices? | likely no (boot-property gated) |
| Can the race be triggered from userland? | **AGX user client excluded** — see §11 |
| How wide is the b1 window on silicon? | device question |

---

## 11. Reachability — AGX user client excluded

A fix tells you what was broken. It does not tell you whether anything could
reach it.

For this race to be meaningful, an unprivileged process must be able to drive
a UAT stage-2 mapping mutation — a map, unmap, or permission change that SPTM
performs on behalf of the GPU — at a moment it can control. The relevant
surface is the GPU driver's user client.

This analysis identified `AGXDeviceUserClient` in `com.apple.AGXG18P` as the
only user client class in the GPU kext, and located its dispatch function.

**Result: the AGX user client does not reach UAT mutation.**

`externalMethod` at `0xfffffe00085553b0` bounds-checks the selector against 17
and jumps through a table of 32-bit offsets at `0xfffffe0008557020`. Of the 18
selector values (0–17), 12 are live and 6 fall through to a shared error path
at `0xfffffe00085569ec`.

Every live handler is a thin stub that tail-calls into a shared body at
`0xfffffe00085555ec`, forwarding a small integer (e.g. `#0x2e60`, `#0x2e58`)
and — for at least one selector — the string `pre_sample_idx`. That shared body
calls virtual methods through PAC-signed dispatch thunks
(`0xfffffe00085c04f0`, `0xfffffe00085c1210`) and passes `#0x20` as a buffer
size.

The shape is **statistical sampling / power telemetry**, not mapping: an
index into a sample array, a fixed 32-byte destination, and a getter-style
interface. Nothing in the sixteen selector paths issues an unmap, changes a
permission, or touches a stage-2 table.

This is a negative result and it is a useful one: **on this build the AGX user
client is not a plausible driver for the UAT mutation the SPTM gate guards.**
Reachability for the race therefore remains unexplained by this surface.

That does not prove reachability is impossible. UAT mutations may be driven by
in-kernel paths not reachable from userland, or by a user client in another
kext. But `AGXDeviceUserClient` — the most obvious candidate — is excluded.

---

## 12. Corrections log

Recorded because they are instructive about method, not because they are
embarrassing:

1. **`vm_protect_privileged_from_untrusted`** was initially read as a removed
   privilege boundary. It has two writers and **zero readers** in b1. Dead
   instrumentation. The name carried more weight than the dataflow.
2. **Gate offset** was initially reported as `state+0x148`; it is `state+0x91`.
   Cause: displacement-scaling bug in a scan script — pre-index addressing has
   a different immediate encoding, and `0x148` turned out to be an unrelated
   u64 field.
3. **Spin bound** was initially reported as 7488 (`0xd40`). The instruction is
   `movz w9,#0xd40` followed by `movk w9,#0x3, lsl #16`; the bound is
   `0x30d40` = 200,000. Stopping at the `movz` produced a plausible-looking
   wrong constant.
4. **`S3_3_C4_C2_1`** was first guessed to be the second half of the Dekker
   protocol. It is read *inside* the critical section, not to acquire it. The
   access pattern ruled this out.
5. **`S3_3_C14_C0_6`** was called an "epoch counter"; it is a tick counter and
   it pre-existed in b1.

The lesson, applied from §5 onward: **resolve the access pattern before
naming the thing.** Four of these five errors came from reading an identifier
and inferring behaviour instead of reading the code that consumes it.

---
## Appendix A — Tooling

All scripts are plain Python 3 with no third-party dependencies. The only
non-stdlib dependency is `libcompression.dylib`, which ships with macOS.

### A.1 `dec.py` — im4p → LZFSE → Mach-O

```python
#!/usr/bin/env python3
import ctypes, sys

SZ = ctypes.c_size_t
lib = ctypes.CDLL("/usr/lib/libcompression.dylib")
lib.compression_decode_buffer.restype = SZ
lib.compression_decode_buffer.argtypes = [
    ctypes.c_void_p, SZ, ctypes.c_void_p, SZ, ctypes.c_void_p, ctypes.c_int]

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
    return d[start:(end + 4) if end > 0 else len(d)]

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("usage: dec.py <im4p> <out.bin>"); raise SystemExit(2)
    out = decode(unwrap_im4p(sys.argv[1]))
    open(sys.argv[2], 'wb').write(out)
    print("%s -> %s (%d bytes)" % (sys.argv[1], sys.argv[2], len(out)))
```

**Note on `argtypes`:** the ctypes signature must be
`(dst, dst_size, src, src_len, scratch, algo)` — six arguments, **not** seven.
Declaring the wrong arity silently produces `0` from
`compression_decode_buffer` and looks exactly like corrupt input. This cost
real time during the analysis.

**Note on stream extent:** the whole im4p payload is **one** LZFSE stream from
`bvx2` to `bvx$`, not a sequence of independent chunks. The string `bvx2`
recurs ~11 times inside the compressed data by coincidence; treating each as a
chunk boundary fails.

### A.2 `sptm.py` — parser, xref scanner, string resolver

```python
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
            if cmd == 0x19:                                    # LC_SEGMENT_64
                b = d[p:p+size]
                out.append(dict(fileoff=struct.unpack_from("<Q", b, 40)[0],
                                vmaddr =struct.unpack_from("<Q", b, 24)[0],
                                filesize=struct.unpack_from("<Q", b, 48)[0],
                                name   =b[8:24].rstrip(b'\0').decode()))
            p += size
        return out

    def vm2off(self, vm):
        for s in self.segs:
            if s['vmaddr'] <= vm < s['vmaddr'] + s['filesize']:
                return s['fileoff'] + (vm - s['vmaddr'])

    def off2vm(self, off):
        for s in self.segs:
            if s['fileoff'] <= off < s['fileoff'] + s['filesize']:
                return s['vmaddr'] + (off - s['fileoff'])

    def text(self):
        return [s for s in self.segs if s['name'] == '__TEXT_EXEC'][0]

    def xrefs(self, target):
        """adrp+add / adrp+ldr references to a VM address."""
        t = self.text(); out = []
        for off in range(t['fileoff'], t['fileoff'] + t['filesize'] - 16, 4):
            w = struct.unpack_from("<I", self.d, off)[0]
            if (w & 0x9f000000) != 0x90000000:                 # ADRP
                continue
            imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
            if imm & (1 << 20): imm -= (1 << 21)
            pc = t['vmaddr'] + (off - t['fileoff'])
            page = (pc & ~0xfff) + (imm << 12)
            for k in (1, 2):
                w2 = struct.unpack_from("<I", self.d, off + 4*k)[0]
                if (w2 & 0xff800000) == 0x91000000 and page + ((w2 >> 10) & 0xfff) == target:
                    out.append(pc)                             # ADD
                elif (w2 & 0xffc00000) == 0xf9400000 and page + ((w2 >> 10) & 0xfff)*8 == target:
                    out.append(pc)                             # LDR
        return out

    def string_at(self, vm, maxlen=160):
        o = self.vm2off(vm)
        if o is None: return None
        e = self.d.find(b'\0', o)
        if e < 0 or e - o > maxlen: return None
        try: s = self.d[o:e].decode('ascii')
        except UnicodeDecodeError: return None
        return s if len(s) >= 4 else None

    def find_str(self, needle):
        i = self.d.find(needle.encode() if isinstance(needle, str) else needle)
        return None if i < 0 else self.off2vm(i)

    def func_start(self, vm, maxback=0x4000):
        o = self.vm2off(vm)
        for back in range(0, maxback, 4):
            if struct.unpack_from("<I", self.d, o - back)[0] in (0xd503237f, 0xd503233f):
                return vm - back
```

### A.3 `scan_flag.py` — load/store census

The script that produced the gate-byte finding. **The critical detail is
addressing-mode decoding**: `0x38491d4b` is a *pre-index* `ldrb w11,[x10,#0x91]!`
and naive decoders mis-read it.

```python
from sptm import SPTM
import struct

DISP = 0x91
s3 = SPTM("24B5099f/sptm.bin"); t = s3.text()

def decode_ls(w):
    rt = w & 0x1f; rn = (w >> 5) & 0x1f
    if (w & 0x3b000000) == 0x39000000:            # unsigned immediate
        size = (w >> 30) & 3; opc = (w >> 22) & 3
        disp = ((w >> 10) & 0xfff) * (1 << size)  # <-- SCALED by access size
        return (('LDR' if opc & 1 else 'STR') + 'BHXW'[size], rn, rt, disp, 'uoff')
    if (w & 0x3b200c00) == 0x38000c00:            # post/pre-index, unscaled
        size = (w >> 30) & 3; opc = (w >> 22) & 3
        imm9 = (w >> 12) & 0x1ff
        if imm9 & 0x100: imm9 -= 0x200
        mode = (w >> 10) & 3
        return (('LDR' if opc & 1 else 'STR') + 'BHXW'[size], rn, rt, imm9,
                {1:'post', 3:'pre'}.get(mode, 'unscaled'))

for off in range(t['fileoff'], t['fileoff'] + t['filesize'] - 8, 4):
    w = struct.unpack_from("<I", s3.d, off)[0]
    r = decode_ls(w)
    if r and r[3] == DISP:
        print("%#x %-6s base=x%-2d rt=x%-2d (%s)" % (t['vmaddr'] + (off - t['fileoff']),) + r)
```

Two bugs this file exists to avoid:

1. **Displacement scaling.** For `LDR/STR (unsigned immediate)` the encoded
   `imm12` is scaled by the access size. Comparing raw `imm12` to a byte
   displacement misses every 64-bit access (`imm12*8`) and every 32-bit one
   (`imm12*4`).
2. **Pre/post-index.** `0x38491d4b` has `mode == 3` (pre-index) with
   `imm9 = 0x91`. Reading it as post-index makes the offset look like 0.

### A.4 `fdiff.py` — relocation-normalised function diff

`adrp` page immediates and branch targets shift with load address, so a raw
byte diff of two builds reports ~97% difference even for unchanged functions.
This canonicalises:

| instruction | normalised to |
|---|---|
| `ADRP` | `("ADRP", rd)` — page dropped |
| `BL` / `B` | target dropped |
| `B.cond`, `CBZ` | condition kept, offset dropped |
| everything else | raw word kept |

Anything not covered by the first three columns is compared verbatim, which
means real structural changes surface and relocation noise does not.

### A.5 `disasm_sptm.py` — inline AArch64 disassembler

Subset sufficient for XNU/SPTM: `adrp`, `add`/`sub` immediate,
`ldr`/`str` (X and W, unsigned offset), `mov` (wide immediate), `b`, `bl`,
`b.cond`, plus the PAC/BTI landing pads (`pacibsp`, `paciasp`, `bti`, `ret`,
`retab`). Prints `.word <hex>` for anything outside the subset rather than
guessing — which is how the `movz`/`movk` pair and the undocumented
system-register instructions were spotted as "outside the subset" and then
decoded by hand.

### A.6 Kernelcache-side tools

Live in `kc/24A446__iPhone18,4/`:

| file | purpose |
|---|---|
| `xref.py` | adrp+add/ldr xref scanner for kernelcache strings |
| `disasm.py` | kernelcache AArch64 disassembler |
| `../24A446__iPhone18,1/analysis/kc.py` | MH_FILESET parser + query CLI |
| `../24A446__iPhone18,1/analysis/fixups.py` | arm64e chained-fixup decoder |
| `../24A446__iPhone18,1/analysis/rebase_blob.py` | emit rebased per-section blobs |
| `../24A446__iPhone18,1/analysis/ida_load.py` | IDA bootstrap for MH_FILESET |

---

## Appendix B — Reproduction

### Step 1 — extract SPTM from the IPSWs

`Firmware/sptm.t8150.release.im4p` is present in all three restore images.

```bash
mkdir -p sptm/{24A446,24B5084k,24B5099f}

unzip -o -j iPhone18,4_27.0.1_24A446_Restore.ipsw \
      "Firmware/sptm.t8150.release.im4p" -d sptm/24A446
unzip -o -j iPhone18,4_27.2_24B5084k_Restore.ipsw \
      "Firmware/sptm.t8150.release.im4p" -d sptm/24B5084k
unzip -o -j iPhone18,4_27.2_24B5099f_Restore.ipsw \
      "Firmware/sptm.t8150.release.im4p" -d sptm/24B5099f
```

Verify you have three different files (27.0.1 and b1 SPTM are the *same
build*, but the im4p envelopes differ in padding):

```bash
shasum -a 256 sptm/*/sptm.t8150.release.im4p
```

### Step 2 — decompress to Mach-O

```bash
cd sptm
python3 dec.py 24A446/sptm.t8150.release.im4p     24A446/sptm.bin
python3 dec.py 24B5084k/sptm.t8150.release.im4p   24B5084k/sptm.bin
python3 dec.py 24B5099f/sptm.t8150.release.im4p   24B5099f/sptm.bin
```

Expected sizes: **1,261,600** bytes for 27.0.1 and b1, **1,327,136** for b3.
Each should begin with `cffaedfe` (little-endian `MH_MAGIC_64`).

### Step 3 — confirm the scale of the change

```bash
python3 - <<'P'
from sptm import SPTM
import struct

def text_section(s):
    """Return (fileoff, size, vmaddr) of the __text SECTION in __TEXT_EXEC."""
    d = s.d
    n = struct.unpack_from("<I", d, 16)[0]; p = 32
    for _ in range(n):
        cmd, size = struct.unpack_from("<II", d, p)
        if cmd == 0x19:
            b = d[p:p+size]
            if b[8:24].rstrip(b'\0') == b'__TEXT_EXEC':
                ns = struct.unpack_from("<I", b, 64)[0]
                for k in range(ns):
                    sb = b[72+k*80:72+(k+1)*80]
                    if sb[0:16].rstrip(b'\0') == b'__text':
                        return (struct.unpack_from("<I", sb, 48)[0],
                                struct.unpack_from("<Q", sb, 40)[0],
                                struct.unpack_from("<Q", sb, 32)[0])
        p += size

for lbl, f in (("b1","24B5084k/sptm.bin"), ("b3","24B5099f/sptm.bin")):
    s = SPTM(f)
    fo, sz, vm = text_section(s)
    dmb = sum(1 for o in range(len(s.d)-4)
              if s.d[o:o+4] == bytes.fromhex('bf3f03d5'))
    print("%s __text size %#x  dmb ish %d" % (lbl, sz, dmb))
P
```

> Note: `s.text()` returns the **segment** (`__TEXT_EXEC`, size `0x68000`).
> The `+3,320 B` figure in §2 is the **section** (`__text`) inside it. Do not
> confuse them — the segment size is identical in both builds, so using it
> would make the change look like zero.

Expected:

```
b1 __text 0x61340  dmb ish 3
b3 __text 0x62038  dmb ish 27
```

The `dmb ish` ratio is the single fastest signal that this release changes
ordering rather than logic.

### Step 4 — locate the flush entry point

```bash
python3 - <<'P'
from sptm import SPTM
s3 = SPTM("24B5099f/sptm.bin")
t = s3.find_str("uat_sync_outer_tlb_sapt_flush")
print("string vm:", hex(t))
for x in s3.xrefs(t):
    print("  xref %#x  func %#x" % (x, s3.func_start(x)))
P
```

Expected:

```
string vm: 0xfffffff027005467
  xref 0xfffffff0270c8018  func 0xfffffff0270c7acc
  xref 0xfffffff0270c8afc  func 0xfffffff0270c8620
  xref 0xfffffff0270c9d94  func 0xfffffff0270c98fc
  xref 0xfffffff0270cb1d0  func 0xfffffff0270cad88
  xref 0xfffffff02710b24c  func 0xfffffff02710a354
```

### Step 5 — find the gate byte

```bash
python3 scan_flag.py
```

Expected: five `LDRB ... (pre)` sites and one `STRB` — the five tests and the
single release.

### Step 6 — pair the functions across builds

Anchor each b3 function by an internal string, then locate its b1 twin:

```bash
python3 - <<'P'
from sptm import SPTM
s3 = SPTM("24B5099f/sptm.bin"); s1 = SPTM("24B5084k/sptm.bin")
for a in ("sptm_uat_remove_ctx_id",
          "sapt_update_permissions_uat_unmap_sync",
          "sptm_uat_prepare_fw_unmap_continue",
          "uat_state_get_root_table_paddr"):
    t3, t1 = s3.find_str(a), s1.find_str(a)
    f3 = s3.func_start(s3.xrefs(t3)[0]) if t3 else None
    f1 = s1.func_start(s1.xrefs(t1)[0]) if t1 else None
    print("%-42s b1 %s  b3 %s" % (a, hex(f1) if f1 else "-", hex(f3) if f3 else "-"))
P
```

Expected pairs (b3 is `+0x10000` from b1 for the first three):

```
sptm_uat_remove_ctx_id                      b1 0xfffffff0270b7acc  b3 0xfffffff0270c7acc
sapt_update_permissions_uat_unmap_sync      b1 0xfffffff0270b847c  b3 0xfffffff0270c8620
sptm_uat_prepare_fw_unmap_continue          b1 0xfffffff0270b95b0  b3 0xfffffff0270c98fc
uat_state_get_root_table_paddr              b1 0xfffffff0270b8100  b3 0xfffffff0270c82a4
```

The first three grow ~0x1A8; the accessor grows by **0**.

### Step 7 — decode the timeout constants

```bash
python3 - <<'P'
# movz + 3x movk builds a 64-bit constant. Do NOT stop at the movz.
seq = [0xd28432e9, 0xf2aeb1c9, 0xf2c36e29, 0xf2e001a9]
val = 0
for w in seq:
    hw, imm = (w >> 21) & 3, (w >> 5) & 0xffff
    val = (val & ~(0xffff << (16*hw))) | (imm << (16*hw))
print("multiplier %#x  == ceil(2^65/10^4): %s" % (val, val == (1<<65)//10000 + 1))

# timeout: movz w9,#0xd40 ; movk w9,#0x3,lsl #16
t = (0xd40) | (0x3 << 16)
print("timeout 0x%x = %d ticks" % (t, t))
for hz in (24_000_000, 25_000_000):
    print("  @ %d Hz = %.2f ms" % (hz, 1000*t/hz))
P
```

Expected:

```
multiplier 0xd1b71758e2197  == ceil(2^65/10^4): True
timeout 0x30d40 = 200000 ticks
  @ 24000000 Hz = 8.33 ms
  @ 25000000 Hz = 8.00 ms
```

### Step 8 — verify the status register is not a counter

The decisive test. A timeout loop needs a comparison; a wait needs a loop.

```bash
python3 - <<'P'
from sptm import SPTM
import struct
s3 = SPTM("24B5099f/sptm.bin"); t = s3.text()
masked = compared = polled = 0
for off in range(t['fileoff'], t['fileoff'] + t['filesize'] - 0x30, 4):
    w = struct.unpack_from("<I", s3.d, off)[0]
    if (w & 0xffffffe0) != 0xd53b4220:            # MRS S3_3_C4_C2_1
        continue
    vm = t['vmaddr'] + (off - t['fileoff'])
    for k in range(1, 6):
        w2 = struct.unpack_from("<I", s3.d, off + 4*k)[0]
        if (w2 & 0x7f800000) == 0x72000000: masked += 1      # ANDS/TST imm
        if (w2 & 0xff800000) == 0x71000000 and (w2 & 0x1f) == 31:
            compared += 1                                     # CMP imm
        if (w2 & 0xff000010) == 0x54000000:
            imm = (w2 >> 5) & 0x7ffff
            if imm & (1 << 18): imm -= (1 << 19)
            if vm + 4*k + (imm << 2) <= vm: polled += 1       # backward branch
print("masked %d  compared %d  polled %d" % (masked, compared, polled))
P
```

Expected: `masked 16  compared 0  polled 0`.

Zero comparisons excludes counter semantics. Zero backward branches excludes
"wait for quiesce."

### Step 9 — the AGX reachability check (negative result)

```bash
cd ../kc/24A446__iPhone18,4
python3 - <<'P'
import struct
b3 = open("kernelcache.release.iPhone18,4.24B5099f", 'rb').read()
TX_FO, TX_VM, TX_SZ = 0x14e5960, 0xfffffe00084e9960, 0xd81d0
def v2o(vm): return TX_FO + (vm - TX_VM)
def sx(v, b): return v - (1 << b) if v & (1 << (b - 1)) else v

pc = 0xfffffe00085553fc
w = struct.unpack_from("<I", b3, v2o(pc))[0]
imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
page = (pc & ~0xfff) + (sx(imm, 21) << 12)
w2 = struct.unpack_from("<I", b3, v2o(pc + 4))[0]
tbl = page + ((w2 >> 10) & 0xfff)
print("AGX jump table @ %#x" % tbl)
for i in range(18):
    off = struct.unpack_from("<i", b3, v2o(tbl + i*4))[0]
    print("  sel %2d -> %#x" % (i, 0xfffffe0008555408 + off))
P
```

Expected (verified):

```
AGX jump table @ 0xfffffe0008557020
  sel  0 -> 0xfffffe0008555414
  sel  1 -> 0xfffffe00085554a8
  sel  2 -> 0xfffffe000855544c
  sel  3 -> 0xfffffe0008555520
  sel  4 -> 0xfffffe0008555560
  sel  5 -> 0xfffffe00085569ec      <- error path
  sel  6 -> 0xfffffe00085569ec
  sel  7 -> 0xfffffe00085569ec
  sel  8 -> 0xfffffe0008555470
  sel  9 -> 0xfffffe00085554c4
  sel 10 -> 0xfffffe00085569ec
  sel 11 -> 0xfffffe00085554f4
  sel 12 -> 0xfffffe00085555c0
  sel 13 -> 0xfffffe00085569ec
  sel 14 -> 0xfffffe00085555a0
  sel 15 -> 0xfffffe00085569ec
  sel 16 -> 0xfffffe0008555430
  sel 17 -> 0xfffffe000855548c
```

12 distinct handlers, 6 slots routing to the shared error path at
`0xfffffe00085569ec`. Every handler tail-calls `0xfffffe00085555ec`, which
loads a virtual method through a PAC dispatch thunk and passes `#0x20` as a
buffer size — the sampling interface described in §11.

---

## Appendix C — Known pitfalls

Collected so the next person does not repeat them.

| pitfall | symptom | correct approach |
|---|---|---|
| `ctypes` arity on `compression_decode_buffer` | returns `0`, looks like corrupt data | 6 args: `(dst, dst_sz, src, src_len, scratch, algo)` |
| Treating every `bvx2` as a chunk | partial / failed decode | one stream, `bvx2` … `bvx$` |
| `imm12` not scaled by access size | misses all 64-bit loads/stores | `disp = imm12 * (1 << size)` |
| Pre-index read as post-index | offset looks like 0 | `mode = (w>>10)&3`; 3 = pre, 1 = post |
| Stopping at `movz` | plausible wrong constant (7488 vs 200000) | follow the `movk` chain |
| `sf` assumed instead of read | `DecodeBitMasks` returns `0x0`, a valid-looking answer | read width from bit 31 |
| Raw byte diff of `__text` | ~97% "changed" from relocation alone | normalise `adrp`/branch immediates |
| Vtable mistaken for dispatch table | in/out counts are garbage | check that the second dword is small |
| Kext `__LINKEDIT` offsets used as file offsets | sections past EOF | segments are **virtual**; translate via the outer container |


---

## Credits

- opa334 for the information about SPTM bypass patch
- Lakr233 for TLB research idea
- YuJunZhiXue for the dsh-purge plugin, this work wouldn't be possible without it
