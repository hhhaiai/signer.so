# ARM64 correction and context-flag leaves

## Correction wrappers

The following functions all have the same exact ordering:

```cpp
writeOrReplaceProtectedCorrection(context + 0x20, code);
store64(context + 0xe0, load64(context + 0xe0) | 1);
```

| ARM64 range | code | C++ entry |
|---|---:|---|
| `0x80c0..0x80f4` | `0x2b` | `applyProtectedCorrection2b` |
| `0x80f4..0x8128` | `0x39` | `applyProtectedCorrection39` |
| `0xd428..0xd45c` | `0x34` | `applyProtectedCorrection34` |
| `0xd980..0xd9b4` | `0x37` | `applyProtectedCorrection37` |
| `0xe674..0xe6a8` | `0x38` | `applyProtectedCorrection38` |
| `0x14ef8` true-result branch | `0x2f` | `applyProtectedCorrection2f` |
| `0x150b8..0x150ec` | `0x3b` | `applyProtectedCorrection3b` |

The correction write precedes the flag load.  The C++ common body
`applyProtectedCorrectionAndFlagBit0` preserves that ordering.

## Flag-only leaves

| ARM64 range | exact OR mask | x86_64 confirmation | C++ entry |
|---|---:|---:|---|
| `0xd45c..0xd474` | `0x0010000000000200` | `0x11789` | `applyProtectedContextMask0010000000000200` |
| `0xd9b4..0xd9cc` | `0x0080020000000000` | `0x11c0e` | `applyProtectedContextMask0080020000000000` |
| `0xe6a8..0xe6c0` | `0x0100040000000000` | `0x12532` | `applyProtectedContextMask0100040000000000` |
| `0x7bb98..0x7bbb0` | `0x000000003dffe800` | `0x7c32f` | `applyProtectedContextMask000000003dffe800` |
| `0x13078..0x13088` | `0x0000000200000000` | `0x15eb6` | `applyProtectedContextBit33` |
| `0x150ec..0x15104` | `0x0800800000000000` | `0x175c3` | `applyProtectedContextMask0800800000000000` |

These are context risk/correction flags.  They do not inspect request
parameters and are not cryptographic algorithm selectors.

## Nested fallback stage

`0x13044..0x13078` performs:

```cpp
sub_7bb98(context);            // OR 0x000000003dffe800
flags |= 0x0000000002001000;
```

x86_64 `0x15ea0` confirms the same call followed by immediate `0x02001000`.

`0x13000..0x13044` performs, in order:

```cpp
flags |= 0x00001181c000010e;
sub_13044(context);
flags |= 0x0000000200000000;
```

x86_64 `0x15e7d` confirms the first 64-bit immediate, the call to `0x15ea0`,
and the final byte OR at `context+0xe4`, which is bit 33 of the 64-bit field.

The implementation deliberately preserves the three load/OR/store stages
rather than collapsing them into one mask because the native function exposes
the nested call boundary and write order.

## ART/linker stat post-stage `0x14ef8`

`0x14ef8..0x150b8` initializes status to zero and calls recovered stat helper
`0xf18f4` with the fixed global target at `0x13ec00`.  Its boolean and status
have independent effects:

```cpp
if (statHelper(&status, fixedTarget)) correction(0x2f), flags |= 1;
if (status != 0)                     correction(0x3b), flags |= 1;
flags |= 0x0800800000000000;
```

x86_64 `0x17453..0x175aa` confirms the same true-result correction, nonzero
status gate, and final `0x0800800000000000` mask.  A true return with nonzero
status therefore emits both corrections in that order.

## `0x9279c`

`0x9279c..0x927ac` ignores ABI arguments 0 and 1 and ORs bit zero into the
context passed as argument 2.  Stage 1 now calls the owned C++ leaf
`applyProtectedContextBit0` directly; the local status remains relevant only
to the preceding `0xf328`/fallback control flow.
