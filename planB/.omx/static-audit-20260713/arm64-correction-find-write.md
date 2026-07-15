# arm64 correction slot find/write pipeline

This report uses only local ARM64 and x86_64 ELF disassembly. The target SO
was not loaded or executed.

## State layout

All three helpers receive the same halfword-addressed state base. The consumed
regions are:

```text
byte +0x10: 16 uint16 codeword basis values
byte +0x30: 64 uint16 writable correction slots
byte +0xb0:  8 uint16 repeating unused-slot sentinels
```

## `0x134dd8..0x134f40`: replacement-slot finder

ARM64 `0x134e5c..0x134f38` and x86_64 `0x12f0dd..0x12f167` implement:

```cpp
uint64_t index = 0;
while (index < 64
       && state[24 + index] != state[88 + (index & 7)]) {
    ++index;
}
return index;
```

The comparison is 16-bit. The exhaustion result is exactly 64, not a failure
code or clamped slot index.

## `0x13531c..0x13548c`: state-local writer

ARM64 clears `state + 0x30 + 2*index` at `0x135398..0x1353bc`. x86_64 does the
same at `0x12f49d..0x12f4a2`. It forms the low 16 bits of `2*code+3`, scans bits
0 through 15, and for every set bit XORs the state-local basis element at
`state[8 + (15-bit)]`. ARM64's XOR/write is `0x135418..0x135430`; the x86_64
equivalent is `0x12f545..0x12f556`.

The clear occurs before basis accumulation and the final halfword write. There
is no capacity check. Therefore finder result 64 makes the destination
`state[24+64] == state[88]`, aliasing and replacing sentinel 0. The C++ keeps
this native behavior rather than adding a safety clamp.

## `0x13548c..0x1354bc`: wrapper

ARM64 preserves the original state and code, calls the finder at `0x1354a0`,
moves its result into argument 2, and tail-branches to the writer at
`0x1354b8`. x86_64 `0x12f5ad..0x12f5ca` has the same sequence. It has no
additional branch, status value, allocation or return transformation.

## C++ parity

`native-reimplementation/recovered_primitives.cpp` now contains:

```text
findProtectedCorrectionReplacementIndex
writeProtectedCorrectionCodeword
writeOrReplaceProtectedCorrection
```

Static regression source covers first-slot replacement, the next-slot scan,
state-local basis parity with `encodeCorrection`, exhaustion result 64, and the
native sentinel-0 overwrite on exhaustion.
