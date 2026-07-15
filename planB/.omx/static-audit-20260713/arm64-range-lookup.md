# arm64 protected range lookup

This report is based only on ELF disassembly. It does not load or execute the
target shared object.

## `0x12e95c..0x12eb48`: unsigned 96-bit compare

The function receives `(x0,w1)` and `(x2,w3)`. It compares unsigned limbs in
this order:

```text
w1 / w3                   most significant 32 bits
x0[63:32] / x2[63:32]     middle 32 bits
x0[31:0] / x2[31:0]       least significant 32 bits
```

It returns `-1`, `0` or `1`.

## `0x12eb48..0x12ec1c`: final-boundary predicate

The returned bit is equivalent to:

```cpp
low32(query) == low32(boundary)
&& (middle32(query) > middle32(boundary)
    || (middle32(query) == middle32(boundary)
        && high32(query) >= high32(boundary)))
```

## `0x13716c..0x137894`: flattened range scan

Boundary records have stride `0x20`; only offsets `+0x00` and `+0x08` are
consumed as the 96-bit boundary value:

```cpp
struct ProtectedRangeBoundary {
    uint64_t low64;       // +0x00
    uint32_t high32;      // +0x08
    uint8_t reserved[20];
};
```

The index starts at zero and increments by one. For every non-final element it
tests:

```text
compare(query, current) >= 0
&& compare(query, next) < 0
```

This is a half-open interval `[current,next)`. A match returns the caller's
input `x4` success cookie. A non-match advances to the next record. The final
record uses `0x12eb48`; exhaustion returns null.

The values carried in `x5/x6` only contribute high halves that the two compare
helpers never consume, so they do not affect the observable lookup result.

This helper is a table/range predicate, not a cryptographic algorithm selector.
