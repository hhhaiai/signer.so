# ARM64 `0x8746c` detector property-materialization pipeline

## Scope and status

This document closes the thirteen system-property materialization stages inside
the still-large producer:

```text
ARM64:  0x8746c..0x8f56c
x86_64: 0x88475..0x93f86
```

It does **not** mark the whole FDE recovered.  The remaining producer proof is
the JNI/sensor/display orchestration, local-reference/UTF cleanup, pair append
loop, complete exit-state ordering and destructor-safe ownership envelope.

## User-input boundary

Only property identifiers and scratch offsets are intrinsic to the native
protocol.  Property **values are not constants** and are not synthesized by the
reimplementation.

The C++ subpipeline receives values through:

```cpp
struct RecoveredDetectorPropertyOperations8746c {
    std::int32_t (*readProperty)(const char* name, char* output);
    void* (*allocate)(std::uint64_t size);
};
```

Therefore a caller can supply real-device properties, a user-authored profile,
empty values or deterministic regression data.  The one-time `TRACE_*` values
in the Unidbg evidence log were temporary differential markers; they were
removed from the Java test source after the trace and do not appear as C++
defaults.

## Cross-ABI field map

| Runtime order | Property identifier | Scratch offset | ARM64 call / name VMA | x86_64 call / name VMA |
|---:|---|---:|---:|---:|
| 1 | `ro.bootloader` | `+0x48` | `0x8d278` / `0x143668` | `0x92636` / `0x13c038` |
| 2 | `ro.product.manufacturer` | `+0x08` | `0x8b244` / `0x143690` | `0x90dc2` / `0x13c060` |
| 3 | `ro.product.model` | `+0x18` | `0x8dd00` / `0x1436b0` | `0x8ebd4` / `0x13c080` |
| 4 | `ro.product.device` | `+0x20` | `0x8c0e8` / `0x143720` | `0x8e7df` / `0x13c0f0` |
| 5 | `ro.build.display.id` | `+0x28` | `0x8eea8` / `0x143900` | `0x92231` / `0x13c2d0` |
| 6 | `ro.product.name` | `+0x00` | `0x8b5b8` / `0x143790` | `0x93daf` / `0x13c160` |
| 7 | `ro.build.host` | `+0x58` | `0x8e95c` / `0x143648` | `0x8f311` / `0x13c018` |
| 8 | `ro.build.fingerprint` | `+0x30` | `0x8d2fc` / `0x1437c0` | `0x8fd4d` / `0x13c190` |
| 9 | `ro.build.type` | `+0x38` | `0x8b7ac` / `0x144800` | `0x8ff6f` / `0x13d2a0` |
| 10 | `ro.product.brand` | `+0x10` | `0x8d9b0` / `0x143700` | `0x92bc0` / `0x13c0d0` |
| 11 | `ro.build.user` | `+0x50` | `0x8b368` / `0x144810` | `0x8df5b` / `0x13d2b0` |
| 12 | `ro.hardware` | `+0x40` | `0x8b9a8` / `0x143628` | `0x8d9ff` / `0x13bff8` |
| 13 | `ro.product.cpu.abilist` | `+0x68` | `0x8bd74` / `0x144820` | `0x8e3cb` / `0x13d2c0` |

All twenty-six encrypted constants decode independently from the ELF bytes.
The ARM64/x86_64 XOR keys and exact bytes are checked by
`analyze_detector_scratch_property_pipeline_8746c.py`.

## Shared buffer and delayed publication

ARM64 `0x8d248..0x8d278` allocates `0x60` bytes from the stack, zeros them and
passes the buffer to the first `0xd4678` call.  x86_64
`0x9260a..0x92636` independently performs the same `0x60`-byte zeroed stack
allocation.  All thirteen runtime calls reuse that buffer.

The flattened producer is pipelined:

1. read property N into the shared buffer;
2. measure the NUL-terminated value;
3. `malloc(length + 1)` and copy it;
4. immediately before reading property N+1, publish N's allocation;
5. after the final stage, publish the CPU ABI-list allocation at `+0x68`.

The twelve publish-before-next-call edges are visible immediately before calls
2..13 in both ABIs.  The final stores are:

```text
ARM64  0x8ae80  str x9, [x8,#104]
x86_64 0x9080c  mov [rax+0x68],rcx
```

## Allocation failure behavior

Each ABI contains thirteen `malloc` call sites.  Every request is the measured
length plus one.  ARM64 has exactly thirteen failure blocks that place `2` in
the flattened status value and clear the current property slot.  x86_64 has the
same thirteen clears and converges on the common status publication:

```text
0x939d1  push 0x2
0x939d3  pop  rdx
0x939d4  mov  [rbp-0x34],edx
```

Earlier property allocations remain published; later fields remain untouched.
The C++ regression injects an allocation failure at every one of the thirteen
positions and checks status `2`, read/allocation counts and partial scratch
publication.

## Auxiliary dynamic evidence

Observation-only Unidbg hooks did not modify registers, return values, branches,
JNI data or target bytes.  A unique-value profile ran V4, V4-repeat and V5 with
exit code zero.  It proved the flattened runtime order, common property output
buffer and final field mapping.  The normalized log is:

```text
.omx/static-audit-20260713/unidbg-detector-scratch-unique-properties-raw.log
```

A USB-connected authorized Pixel 8 is available for later ART/Bionic-specific
confirmation, but no true-device modification was required for this property
subpipeline.

## C++ and verifier evidence

```text
native-reimplementation/recovered_primitives.cpp
  RecoveredDetectorPropertyOperations8746c
  kRecoveredDetectorPropertyDescriptors8746c
  runRecoveredDetectorProperties8746c
  recoveredDetectorProperties8746cRegression

.omx/static-audit-20260713/analyze_detector_scratch_property_pipeline_8746c.py
```

The producer FDE remains `unknown` until the non-property state machine is also
closed.
