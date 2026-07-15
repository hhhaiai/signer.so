# ARM64 `0x8fb44` detector-scratch content destructor

## Scope

```text
ARM64:  0x8fb44..0x90714
x86_64: 0x94496..0x94d5e
```

Both ranges have dedicated `.eh_frame` FDEs.  Their sole direct callers are:

```text
ARM64  0xfc98: bl   0x8fb44
x86_64 0x138eb: call 0x94496
```

The callers pass the `0x878`-byte stack object at stack `+0x38`, after the
environment stage has finished using it.  This matches
`RecoveredDetectorScratch868b4` exactly.

## Null behavior and call surface

The entry tests the sole argument for null.  Null selects the return state and
performs no load or release.  Each ABI contains exactly ten static `free` call
sites: eight for fixed fields and two shared by the pair-slot loop.

## Fixed owned fields

Flattened-state transitions establish this semantic order:

| Order | Field | x86_64 load | x86_64 free/clear |
|---:|---:|---:|---:|
| 1 | `+0x08` | `0x94824` | `0x94aab` / `0x94ae7` |
| 2 | `+0x18` | `0x949a9` | `0x94913` / `0x9494f` |
| 3 | `+0x20` | `0x949e0` | `0x94a58` / `0x94a94` |
| 4 | `+0x00` | `0x94d23` | `0x94c7d` / `0x94cb9` |
| 5 | `+0x30` | `0x9495f` | `0x94cd0` / `0x94d0c` |
| 6 | `+0x38` | `0x94984` | `0x94a05` / `0x94a41` |
| 7 | `+0x10` | `0x94c5f` | `0x94895` / `0x948d1` |
| 8 | `+0x50` | `0x94c23` | `0x94849` / `0x94885` |

Every field is gated by a null test.  A non-null field is passed to `free` and
then cleared; a null field is skipped.  ARM64 independently contains matching
loads and zero stores at offsets `0,8,16,24,32,48,56,80`.

The helper never accesses `+0x40`.

## Pair-slot sentinel loop

The pair array begins at scratch `+0x70` and uses a 16-byte stride:

```text
slot+0x00  first owned pointer
slot+0x08  second owned pointer
```

ARM64 evidence:

```text
0x90038  base + index*16 + 0x70, load first pointer
0x9015c  free first pointer
0x901f0  clear first pointer
0x9005c/0x90194  load second pointer
0x901f8  free second pointer
0x90220  clear second pointer
0x906d0  increment index
```

x86_64 evidence:

```text
0x94be6  base + index*16 + 0x70, load first pointer
0x94af7  free first pointer and clear slot+0x00
0x948e8/0x94b44  load second pointer
0x94b6a  free second pointer and clear slot+0x08
0x94c41  increment index
```

The recovered loop is:

```cpp
slot = scratch->strings.data();
while (slot->value != nullptr || slot->secondaryValue08 != nullptr) {
    if (slot->value != nullptr) {
        free(slot->value);
        slot->value = nullptr;
    }
    if (slot->secondaryValue08 != nullptr) {
        free(slot->secondaryValue08);
        slot->secondaryValue08 = nullptr;
    }
    ++slot;
}
```

The all-null slot is a terminator and is not modified.

## Important compatibility and safety boundary

The native helper does **not**:

- read `stringCount` at `+0x870`;
- compare the index with 128;
- clear `stringCount`;
- stop after the declared `std::array<...,128>` storage;
- touch `fixedString40`, opaque fields, or the fixed pair at `+0x60/+0x64`.

Therefore a scratch object with no all-null pair among the first 128 slots
causes the native loop to continue beyond the `0x878` object.  It can read
adjacent stack data and may pass non-null adjacent values to `free`.  The known
caller starts from a zeroed scratch object, which normally supplies a sentinel,
but the producer's absolute guarantee that it cannot fill every slot remains a
separate proof obligation.  This is recorded as a memory-safety candidate, not
as a demonstrated attacker-controlled exploit path.

## C++ evidence

```text
native-reimplementation/recovered_primitives.cpp
  runRecoveredDetectorScratchContentDestroy8fb44(..., release)
  runRecoveredDetectorScratchContentDestroy8fb44(...)
  recoveredDetectorScratchContentDestroy8fb44Regression()
```

The regression model proves null no-op, exact fixed-field order, first-before-
second pair cleanup, early all-null sentinel termination, and preservation of
`+0x40`, opaque fields, a later post-sentinel slot, and `stringCount`.

Static verifier:

```text
.omx/static-audit-20260713/analyze_detector_scratch_destructor_8fb44.py
```
