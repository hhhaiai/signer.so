# ARM64 detector context-flag and no-op leaves

## Scope

This note closes twenty context-flag FDE leaves and three standalone no-op FDE
leaves in the authorized ARM64 target:

```text
adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so
```

All twenty flag leaves mutate the low 64 bits at native context byte `+0xe0`:

```cpp
flags = flags | fixedMask;
```

They do not validate the context pointer, write a correction, change status or
return a meaningful value. Reapplying a leaf is idempotent because the only
operation is bitwise OR.

## Exact address-to-mask map

| ARM64 FDE | Mask |
|---:|---:|
| `0x8ad4..0x8aec` | `0x0200080000000000` |
| `0x16b64..0x16b74` | `0x1000000000000000` |
| `0x40fec..0x40ffc` | `0x0000000000000800` |
| `0x418d8..0x418e8` | `0x0000000000002000` |
| `0x421cc..0x421dc` | `0x0000000000004000` |
| `0x430f4..0x43104` | `0x0000000000008000` |
| `0x43998..0x439a8` | `0x0000000000010000` |
| `0x442dc..0x442ec` | `0x0000000000020000` |
| `0x44c28..0x44c38` | `0x0000000000040000` |
| `0x44da0..0x44db0` | `0x0000000000080000` |
| `0x456a8..0x456b8` | `0x0000000000100000` |
| `0x47778..0x47788` | `0x0000000000200000` |
| `0x47f84..0x47f94` | `0x0000000000400000` |
| `0x490e0..0x490f0` | `0x0000000000800000` |
| `0x4afd4..0x4afe4` | `0x0000000001000000` |
| `0x4aff0..0x4b000` | `0x0000000020000000` |
| `0x4b000..0x4b010` | `0x0000000004000000` |
| `0x4b010..0x4b020` | `0x0000000008000000` |
| `0x4d9ac..0x4d9bc` | `0x0000000010000000` |
| `0x927ac..0x927bc` | `0x0001000000000000` |

Nineteen leaves use the exact four-instruction body:

```asm
ldr x8, [x0, #0xe0]
orr x8, x8, #fixedMask
str x8, [x0, #0xe0]
ret
```

`0x8ad4` has the same source-level behavior but materializes its non-logical-
immediate mask through:

```asm
mov  x9, #0x80000000000
movk x9, #0x200, lsl #48
```

before `orr x8, x8, x9`.

## RET-only FDEs

The following are three distinct `.eh_frame` ranges, each containing exactly
one `ret` instruction and no observable mutation:

```text
0x4afe4..0x4afe8
0x4afe8..0x4afec
0x4afec..0x4aff0
```

One shared source-level no-op represents the identical behavior while an
explicit address table preserves function-level coverage.

## C++ recovery

The implementation is in:

```text
native-reimplementation/recovered_primitives.cpp
```

Key symbols:

```text
RecoveredDetectorContextFlagLeaf
kRecoveredDetectorContextFlagLeaves
applyRecoveredDetectorContextFlagLeaf
kRecoveredDetectorNoOpLeaves
runRecoveredDetectorNoOpLeaf4afe4_4afec
recoveredDetectorContextFlagLeavesRegression
```

The regression initializes a nonzero flag word, applies every leaf twice and
checks both the exact OR result and idempotence. It also calls the shared no-op
and proves that the context flag word is unchanged.

## Static verifier

```bash
python3 .omx/static-audit-20260713/analyze_detector_context_flag_leaves.py
```

The verifier checks:

1. every instruction at all twenty ARM64 flag FDEs;
2. the special MOV/MOVK mask at `0x8ad4`;
3. all three RET-only FDE bodies;
4. every address/mask pair in C++;
5. every recovered inventory mapping and generated coverage row;
6. the direct regression and top-level executable guard.

## Coverage effect

This batch changes the authoritative 388-FDE matrix from:

```text
289 recovered / 99 unknown
```

to:

```text
312 recovered / 76 unknown
```

None of these leaves is statically reachable from the two exported JNI entry
points under the current direct-call graph, so the JNI-reachable split remains
`276 recovered / 45 unknown`. Their recovery is still required by the user's
full-file, all-FDE objective.
