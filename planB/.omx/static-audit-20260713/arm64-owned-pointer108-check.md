# ARM64 `context+0x108` string-consistency stage

## Scope

```text
0xcde4..0xd184
```

C++:

```text
runRecoveredOwnedPointer108StringCheck()
```

Repeatable checker:

```text
.omx/static-audit-20260713/analyze_owned_pointer108_check.py
```

## Recovered flow

The local outputs begin as:

```cpp
uint32_t status = 0;
uint64_t scannedData = 0;
```

The fixed threshold is loaded from ARM64 `.rodata+0x08`, VMA/file offset
`0x2f48`:

```text
00 00 00 00 00 4c cd 40 -> little-endian double 15000.0
```

The complete source-level flow is:

```cpp
timingComparison(context, 15000.0);
sub_1709c(&status, &scannedData);

if (status != 0) {
    correction(0x34);
    flags |= 1;
} else {
    timingComparison(context, 15000.0);

    const uint8_t* expected = (uint8_t*)context->ownedPointer108;
    const uint8_t* observed = (uint8_t*)scannedData;
    while (*expected == *observed && *expected != 0) {
        ++expected;
        ++observed;
    }
    if (*expected != *observed) {
        correction(0x09);
        flags |= 1;
    }
}

flags |= 0x0010000000000200;
free((void*)scannedData);
```

## Failure and ownership semantics

- `scannedData` is zero-initialized before `0x1709c`.
- A nonzero status does not dereference either string pointer.
- The failure path emits correction `0x34`.
- The success path has no null guard for `context+0x108` or `scannedData`.
- A byte mismatch, including one string ending before the other, emits
  correction `0x09`.
- Equal NUL terminators finish without correction `0x09`.
- The fixed flag mask is applied on all paths.
- `free(scannedData)` is unconditional and occurs after the flag write;
  therefore a partially assigned output from `0x1709c` is still owned and
  released by this wrapper even when status is nonzero.

The exact producer meaning of `0x1709c` is still being lifted separately.  The
correction behavior is consistent with the already observed command-line
integrity path, but this function-level implementation does not require a
speculative name for the producer.

## Cross-ABI confirmation

x86_64 `0x111bc..0x11519` confirms:

- two calls to timing helper `0x11519` using the same `15000.0` constant;
- producer `0x18909(&status,&scannedData)`;
- load from `context+0x108`;
- byte comparison with explicit unequal/end handling;
- correction `0x09` on mismatch;
- correction helper `0x11770` (`0x34`) on producer failure;
- final mask `0x0010000000000200`;
- unconditional `free@plt(scannedData)`.

This stage mutates integrity/correction state only.  It does not select a
cryptographic algorithm.
