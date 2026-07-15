# ARM64 `0x868b4..0x87158` detector marker matcher

## Function contract

The function has no direct callees. Its three inputs are:

```text
x0 = 0x878-byte detector scratch object
x1 = pointer to an array of C-string marker pointers
x2 = marker count
```

It returns a boolean in `w0`. A zero marker count, null marker-pointer array,
or null scratch pointer returns false without dereferencing the inputs
(`0x868d0..0x869c0`).

## Scratch layout

The only scratch fields consumed by this function are:

```text
+0x070  first 16-byte string slot
        +0x00 C-string pointer
        +0x08 opaque/unused here
        repeated with a 0x10-byte stride

+0x870  uint64 active string-slot count
```

Evidence:

```text
0x86e98  load scratch+0x870
0x86f8c  scratch + index*16
0x86f90  load pointer at resulting +0x70
```

x86_64 `0x87ac8..0x881ea` independently uses the same offsets at
`0x88048` and `0x87fad..0x87fb6`.

## Recovered algorithm

The flattened state machine reduces to:

```cpp
if (markerCount == 0 || markers == nullptr || scratch == nullptr)
    return false;

for (uint64_t i = 0; i < scratch->stringCount; ++i) {
    const char* candidate = scratch->strings[i].value;
    for (uint64_t j = 0; j < markerCount; ++j) {
        if (candidate == nullptr) continue;
        const char* marker = markers[j];
        if (marker == nullptr) continue;
        if (ascii_case_insensitive_full_string_equal(marker, candidate))
            return true;
    }
}
return false;
```

Marker pointers are loaded with an eight-byte stride at `0x86ea4..0x86eb4`.
Candidate and marker bytes are loaded at `0x86f00..0x86f10`. Both ASCII-fold
blocks (`0x86e10..0x86e60` and `0x87010..0x87050`) OR `0x20` only when the
unsigned byte is in `A..Z`. Bytes outside ASCII uppercase are unchanged.

Both cursors advance together only after an equal byte
(`0x870a0..0x870c8`). NUL handling requires both strings to end at the same
position. Therefore this is complete-string equality, not substring search
and not prefix matching. On a match, the flattened return path records that
the current scratch index is still below the scratch count; only exhaustion
produces false (`0x86f58..0x86f70`, `0x87148..0x87154`).

## Source and regression evidence

Direct C++ is implemented as:

```text
RecoveredDetectorStringSlot868b4
RecoveredDetectorScratch868b4
foldRecoveredAsciiDetectorByte868b4
recoveredAsciiCaseInsensitiveEqual868b4
runRecoveredDetectorMarkerMatcher868b4
```

The regression covers invalid inputs, empty scratch, null slots, null markers,
later-slot/later-marker matching, ASCII case folding, both prefix directions,
exact empty-string equality, and empty/nonempty inequality.

Repeatable evidence check:

```bash
python3 .omx/static-audit-20260713/analyze_detector_marker_matcher_868b4.py
```
