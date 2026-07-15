# ARM64 `0x8f56c` detector-scratch owned string-pair appender

## Scope and caller

```text
ARM64:  0x8f56c..0x8fb44
x86_64: 0x93f86..0x94496
```

Both ranges have dedicated `.eh_frame` FDEs and no internal helper callees
other than `malloc`/`free`.  Their sole direct callers pass five arguments:

```text
ARM64  0x8bccc: bl   0x8f56c   // x0..x4
x86_64 0x92f15: call 0x93f86  // rdi,rsi,rdx,rcx,r8
```

Recovered signature:

```cpp
uint32_t append(
    RecoveredDetectorScratch868b4* scratch,
    const uint8_t* firstBytes,
    uint64_t firstLength,
    const uint8_t* secondBytes,
    uint64_t secondLength);
```

## Capacity and sentinel invariant

The helper reads `scratch+0x870` and accepts only counts `0..126`:

```text
ARM64:  ldr x8,[x0,#2160]; cmp x8,#0x7e; fail on HI
x86_64: mov rax,[rdi+0x870]; cmp rax,0x7f; fail on AE
```

Count `>=127` returns `0x26` without allocation or scratch mutation.

On success the count increments by one, so the maximum published count is
127.  Slot 127 remains zero and supplies the all-null sentinel required by the
adjacent `0x8fb44` content destructor.  This explains why the structure owns
128 physical slots but the appender exposes only 127 usable entries.

## Allocation and copy sequence

The semantic sequence is:

```cpp
first = malloc(firstLength + 1);
if (first != nullptr) {
    for (i = 0; i < firstLength; ++i) first[i] = firstBytes[i];
    first[firstLength] = 0;
}

second = malloc(secondLength + 1);
if (second != nullptr) {
    for (i = 0; i < secondLength; ++i) second[i] = secondBytes[i];
    second[secondLength] = 0;
}
```

Evidence:

```text
ARM64 first allocation:  0x8f8a4, size x2+1
ARM64 first copy/NUL:     0x8fa7c / 0x8fb18
ARM64 second allocation: 0x8f7ec, size x4+1
ARM64 second copy/NUL:    0x8f944 / 0x8fa34

x86_64 first allocation:  0x94237, size rdx+1
x86_64 first copy/NUL:     0x94164 / 0x942a7
x86_64 second allocation: 0x9419a, size r8+1
x86_64 second copy/NUL:    0x94318 / 0x941fe
```

The apparent reversed block layout is flattened control flow; the state
transitions execute first allocation/copy before second allocation/copy.

The second allocation is attempted even when the first allocation failed.
Likewise, if the first succeeded, its copy is complete before a second failure
is known.

## Publication and rollback

Only when both allocations are non-null:

```cpp
slot = scratch->strings[scratch->stringCount];
slot.value = first;
slot.secondaryValue08 = second;
++scratch->stringCount;
return 0;
```

ARM64 publication appears at `0x8f874..0x8f89c`; x86_64 publication appears at
`0x942d7..0x94300`.

Failure behavior:

| First allocation | Second allocation | Scratch mutation | Cleanup | Return |
|---|---|---|---|---:|
| success | success | publish pair, increment count | none | `0` |
| failure | success | none | `free(nullptr)`, then `free(second)` | `2` |
| success | failure | none | `free(first)`, then `free(nullptr)` | `2` |
| failure | failure | none | `free(nullptr)`, then `free(nullptr)` | `2` |
| count `>=127` | not attempted | none | none | `0x26` |

The native cleanup contains two unconditional, ordered `free` calls:

```text
ARM64:  0x8f978, 0x8f984
x86_64: 0x94401, 0x94410
```

## Input and arithmetic boundaries

The native function has no checks for:

- null scratch;
- null source with nonzero length;
- whether either source range is readable;
- `length + 1` unsigned wrap;
- allocation size representability beyond the native 64-bit ABI.

For `length == UINT64_MAX`, `length+1` wraps to zero before `malloc`, while the
subsequent copy/NUL logic still uses the original huge length.  This is a
memory-safety candidate if an untrusted length can reach the helper.  The
current caller obtains all four source/length arguments from internal flattened
state; external controllability has not yet been proven.

## C++ evidence

```text
native-reimplementation/recovered_primitives.cpp
  runRecoveredDetectorScratchOwnedPairAppend8f56c(..., operations)
  runRecoveredDetectorScratchOwnedPairAppend8f56c(...)
  recoveredDetectorScratchOwnedPairAppend8f56cRegression()
```

The regression model covers success with embedded zero bytes, capacity status
`0x26`, first-only failure, second-only failure and two-allocation failure.  It
also proves that failure never publishes a partial slot and that cleanup is
first-before-second, including null arguments.

Static verifier:

```text
.omx/static-audit-20260713/analyze_detector_scratch_appender_8f56c.py
```
