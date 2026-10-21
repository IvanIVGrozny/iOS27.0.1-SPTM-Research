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
