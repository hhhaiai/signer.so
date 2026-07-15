# arm64 `0xd184..0xd428` realtime threshold comparison

This report is based only on local ARM64 and x86_64 disassembly and target data
constants. The target SO was not loaded or executed.

## ABI and inputs

The function receives:

```text
x0/rdi   native context
d0/xmm0  threshold in milliseconds
```

It returns no caller-consumed value. Its observable outputs are the double at
context `+0x00` and the low byte at context `+0x08`.

## Clock selection

ARM64 `0xd378..0xd3a4` invokes syscall 113:

```text
clock_gettime(CLOCK_REALTIME, &timespec)
```

x86_64 `0x11692..0x116f5` invokes syscall 228 with the same arguments. The
timespec storage is zero-initialized before the call.

Only the exact result `-ENOSYS` (`-38`) selects the fallback. ARM64 tests it at
`0xd390`; x86_64 at `0x116eb`. Other negative results do not call the fallback
and therefore retain the zero-initialized clock fields.

The fallback is:

```text
gettimeofday(&timeval, nullptr)
```

at ARM64 `0xd334..0xd370` / x86_64 `0x11626..0x1168d`. Its return value is not
tested.

## Millisecond normalization

The target doubles at ARM64 file offsets `0x2f40` and `0x2f50` are:

```text
1000000.0
1000.0
```

ARM64 `0xd3a8..0xd3b8` and x86_64 `0x116fa..0x1171a` compute:

```cpp
milliseconds = double(seconds) * 1000.0
             + double(nanoseconds) / 1000000.0;
```

For the gettimeofday fallback, microseconds are first multiplied by 1000 to
form nanoseconds.

## Context mutation

The controlling input is exactly one byte at context `+0x08`:

```cpp
if (load8(context + 0x08) == 0) {
    storeDouble(context + 0x00, currentMilliseconds);
} else if (currentMilliseconds
           - loadDouble(context + 0x00) > thresholdMilliseconds) {
    store8(context + 0x08, 1);
}
```

The comparison is strict greater-than. Equality, an unordered/NaN comparison,
or a smaller elapsed value leaves the byte unchanged. The byte store preserves
the upper three bytes of the 32-bit word at `+0x08`.

Evidence:

```text
ARM64  0xd1dc       load context byte
ARM64  0xd310       store baseline double
ARM64  0xd3bc..d3c8 elapsed subtraction and strict GT
ARM64  0xd318..d32c write low byte 1

x86_64 0x1155e      compare context byte
x86_64 0x11604..13  store baseline double
x86_64 0x11720..3a  elapsed subtraction and unsigned-FP above selection
x86_64 0x11618..21  write low byte 1
```

## C++ parity

Implemented in `native-reimplementation/recovered_primitives.cpp` as:

```text
ProtectedRealtimeSyscallSamples
protectedRealtimeMilliseconds
applyProtectedTimingComparison
```

Static regression source covers initial baseline storage, strict-threshold
mutation, equality non-mutation, preservation of upper timing-state bytes, and
the exact `-ENOSYS` gettimeofday fallback.
