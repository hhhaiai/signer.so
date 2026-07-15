# ARM64 APK Signing Block entry dispatcher `0x127194..0x127a78`

## Scope

| ABI | FDE range |
|---|---|
| ARM64 | `0x127194..0x127a78` |
| x86_64 | `0x11e1d8..0x11e802` |

This function is the only direct caller of the recovered `0x1259b8` locator.
It consumes the APK Signing Block ID-value entries and publishes parsed signer
structures into the three embedded owners created at outer offsets
`+0x18/+0x28/+0x38`.

## Recovered behavior

```cpp
locateSigningBlock(status, owner);
if (*status != 0) return;

for (;;) {
    uint64_t entrySize = 0;
    if (fread(&entrySize, 8, 1, owner->stream) == 0) return;

    uint32_t entryId = 0;
    if (fread(&entryId, 4, 1, owner->stream) == 0) return;

    uint32_t parsedSize = uint32_t(entrySize) - 4;
    switch (entryId) {
        case 0x7109871a: // APK Signature Scheme v2
            parseV2(status, owner + 0x18, parsedSize, stream);
            break;
        case 0xf05368c0: // APK Signature Scheme v3
            parseV3(status, owner + 0x28, parsedSize, stream);
            break;
        case 0x1b93ad61: // APK Signature Scheme v3.1
            parseV3(status, owner + 0x38, parsedSize, stream);
            break;
        default:
            long current;
            if (!checkedFtell(status, stream, &current)) return;
            if (uint64_t(current) >= uint64_t(owner->field08)
                    + owner->field10) return;
            if (fseek(stream, long(entrySize - 4), SEEK_CUR) != 0) {
                *status = 7;
                return;
            }
            break;
    }

    if (*status != 0) return;
}
```

The direct source implementation uses the semantic owner names proven by
`0x1259b8`:

```text
field08 = signingBlockFooterOffset
field10 = signingBlockSize
```

## Scheme routing

| Signing Block ID | Meaning | ARM64 owner | parser |
|---:|---|---:|---:|
| `0x7109871a` | APK Signature Scheme v2 | `+0x18` | `0x122fe8` |
| `0xf05368c0` | APK Signature Scheme v3 | `+0x28` | `0x124a24` |
| `0x1b93ad61` | APK Signature Scheme v3.1 | `+0x38` | `0x124a24` |

The native opaque CFG implements the switch as a signed decision tree, but the
three equality outcomes above are exact in both ABIs.

ARM64 routing evidence:

```text
0x1275c0  low32(entrySize)-4 -> owner+0x18 -> 0x122fe8
0x1279a4  low32(entrySize)-4 -> owner+0x28 -> 0x124a24
0x127680  low32(entrySize)-4 -> owner+0x38 -> 0x124a24
```

x86_64 uses the same IDs and the corresponding helpers at `0x11b441` and
`0x11c97c`.

## Raw I/O behavior

Unlike most adjacent parsers, the entry loop deliberately calls raw
`fread/fseek` rather than the checked status-2 wrappers.

### Entry header reads

```text
fread(&entrySize, 8, 1, stream)
fread(&entryId,   4, 1, stream)
```

The return value is tested only against zero.  A zero result, including EOF or
a short final item, exits without changing status.  Therefore a truncated
entry header can be accepted as normal loop completion.

### Recognized lengths

For all three recognized IDs, native code loads only the low 32 bits of the
uint64 entry size and subtracts four modulo 32 bits:

```text
parsedSize = uint32(entrySize) - 4
```

The high 32 bits are discarded.  No explicit `entrySize>=4` or
`entrySize<=UINT32_MAX` validation occurs here.

### Unknown-entry skip

Unknown IDs first use checked `ftell`.  The current position is compared
unsigned against the modulo-64-bit sum:

```text
signingBlockFooterOffset + signingBlockSize
```

If current position is greater than or equal to that value, the function exits
without status.  Otherwise it calls raw `fseek` by the full uint64
`entrySize-4`, bit-interpreted as signed `long`.  It does not prove that the
post-seek position remains below the bound.  A nonzero `fseek` result writes
status `7`.

## Input-validation findings

The following behaviors are statically confirmed:

1. raw `fread` zero is a status-preserving successful termination;
2. recognized entry sizes discard the high 32 bits;
3. subtract-four occurs without a minimum-size check;
4. unknown-entry validation checks the position before, not after, the skip;
5. the footer-offset-plus-size bound uses unchecked modulo-64-bit addition;
6. a seek-past-EOF may succeed and will only be observed by a later zero read.

These are parser-hardening weaknesses.  The already recovered nested v2/v3
parsers perform several internal section-size checks, which limits some paths,
but the complete memory-safety impact depends on all downstream allocation and
length combinations.  The finding is therefore classified as medium-risk
candidate rather than a proven out-of-bounds primitive.

## C++ and static regression

Implementation:

```text
native-reimplementation/recovered_primitives.cpp
RecoveredApkSigningBlockEntryOperations127194
runRecoveredApkSigningBlockEntries127194
recoveredApkSigningBlockEntries127194Regression
```

The callback-driven regression represents:

1. ordered v2/v3/v3.1 routing;
2. high-32-bit truncation on recognized entry sizes;
3. full-64-bit unknown-entry seek;
4. bound-stop without seek;
5. raw-fseek status `7`;
6. checked-ftell status `2`;
7. locator failure short circuit;
8. raw ID-read zero normal exit;
9. parser-status propagation and immediate loop termination.

Static verifier:

```text
.omx/static-audit-20260713/analyze_apk_signing_block_entries_127194.py
```

It re-disassembles both ABIs and verifies the raw read loop, all three IDs,
owner routing, 32-bit/full-64-bit length split, unknown-entry bound/seek,
status `7`, C++ operation order and coverage entry.
