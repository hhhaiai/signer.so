# ARM64 `0x7bbb0..0x868b4` fixed-string detector matcher

## Why the FDE is large

The `0xad04`-byte FDE has no direct callees and performs no writes through an
input-derived base. It is a flattened/interleaved expansion of eight copies of
the same marker comparison loop, not a separate cryptographic engine.

Inputs are saved at entry as:

```text
x0 -> scratch pointer       saved at sp+0x158
x1 -> marker pointer array  saved at sp+0x150
x2 -> marker count          saved at sp+0x168
```

The same three-way validation used by `0x868b4` rejects zero count, null marker
array, or null scratch (`0x7bbcc..0x7bc04`).

## Fixed scratch fields

The function reads eight pointer fields from the scratch object:

```text
+0x00, +0x08, +0x10, +0x18,
+0x20, +0x30, +0x38, +0x50
```

The concrete loads are at `0x8335c`, `0x85fec`, `0x821d8`, `0x82100`,
`0x8311c`, `0x8510c`, `0x84b88`, and `0x842e8`. Null fixed fields are skipped.

## Reduced algorithm

For each of those eight fixed strings, the function iterates the caller's
marker array. Static instruction multiplicities close the eight lanes:

```text
8  indexed marker-pointer loads (index * 8)
16 byte loads (candidate + marker for each lane)
16 NUL comparisons
8  marker-index increments
16 string-cursor increments (8 candidate + 8 marker)
```

Each comparison first accepts identical bytes, then folds only ASCII `A..Z`
by OR-ing `0x20`. The disassembly contains sixteen liveness-specific copies of
the folding block, all with the same `byte-'['`, unsigned 26-byte range test,
and folded comparison pattern. Both cursors advance together on an equal byte;
on mismatch, the current marker is abandoned and the marker index advances.
Both NUL bytes must be reached together. Consequently the predicate is exact
case-insensitive full-string equality, not prefix or substring matching.

The only externally observable result writes are:

```text
0x83584..0x8358c  result = 1 on any complete match
0x84d04           result = 0 on invalid/exhausted paths
0x8688c..0x86890  return result & 1
```

Source-level equivalent:

```cpp
for (fixedString in scratch offsets 00/08/10/18/20/30/38/50)
    for (marker in markers[0..count))
        if (fixedString && marker && ascii_case_insensitive_equal(...))
            return true;
return false;
```

The x86_64 initializer does not contain this additional fixed-field prepass;
it calls its fanout and then `0x87ac8`, the equivalent of ARM64's dynamic-slot
`0x868b4` matcher. This is therefore an ARM64-specific detector stage.

## Source and regression evidence

Direct C++ is implemented by
`runRecoveredDetectorFixedMarkerMatcher7bbb0`. The regression covers all eight
fixed offsets independently, invalid inputs, all-null fields, null markers,
ASCII case folding, prefix rejection, and empty-string equality.

Repeatable evidence check:

```bash
python3 .omx/static-audit-20260713/analyze_detector_fixed_matcher_7bbb0.py
```
