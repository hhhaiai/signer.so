# arm64 timing/correction flag helpers

This report is based only on local ARM64 and x86_64 ELF disassembly. The target
SO was not loaded or executed.

## `0xf1c8..0xf1fc`

ARM64 `0xf1d8..0xf1e0` calls the correction writer with
`(context+0x20, 0x33)`. It then loads the 64-bit word at `context+0xe0`, ORs
bit zero, and stores it back at `0xf1e4..0xf1ec`. The x86_64 equivalent is
`0x13021..0x1303a`.

Ordering is observable: correction state is changed before the flags word is
loaded and updated.

## `0xf1fc..0xf214`

ARM64 constructs and ORs this exact 64-bit mask into `context+0xe0`:

```text
0x0008000000000080
```

Evidence is `0xf1fc..0xf20c`; x86_64 `0x1303a..0x1304c` uses the same immediate.

## `0xf214..0xf224`

This helper performs only:

```cpp
contextFlags |= 0x20;
```

ARM64 evidence is `0xf214..0xf21c`; x86_64 is `0x1304c..0x13054`.

## `0xf224..0xf328`

The controlling load at ARM64 `0xf23c` and x86_64 `0x1306a` is one byte from
`context+0x08`, not the full 32-bit timing word. Therefore values such as
`0x100` take the disabled branch because their low byte is zero.

When the byte is nonzero, ARM64 `0xf2d8..0xf2e0` and x86_64
`0x130c0..0x130c7` call the correction writer with:

```text
state = context + 0x20
code  = 0x05
```

The enabled path then ORs context flags with `1`. Both enabled and disabled
paths converge on a final OR with `0x20` at ARM64 `0xf308..0xf314` and x86_64
`0x130e1..0x130e5`.

Equivalent logic is:

```cpp
uint64_t flags = load64(context + 0xe0);
if (load8(context + 0x08) != 0) {
    writeOrReplaceCorrection(context + 0x20, 0x05);
    flags = load64(context + 0xe0) | 1;
}
store64(context + 0xe0, flags | 0x20);
```

The only caller is `nOnResume` at `0xcc26c`. This helper changes correction
material and context state flags; it contains no cipher selection, key
selection, block-mode branch, or cryptographic primitive call.

## C++ parity

The equivalent entries in `native-reimplementation/recovered_primitives.cpp`
are:

```text
applyProtectedCorrection33Gate
applyProtectedContextMask0008000000000080
applyProtectedContextStageCompleteFlag
applyProtectedTimingCorrectionGate
```

Static regression source covers the low-byte-only distinction, enabled and
disabled correction paths, exact masks, correction ordering, and accumulated
flag values.
