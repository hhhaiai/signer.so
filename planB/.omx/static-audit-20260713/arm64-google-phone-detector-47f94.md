# ARM64 `0x47f94..0x490e0` google-phone detector

## Input and gate

- The function saves the scratch pointer and rejects null at `0x47fbc`.
- `0x48ca0..0x48cb8` loads `scratch+0x30`.
- `0x48cd0..0x48cd8` requires both that field and the correction array.

## Ordered predicates

The flattened state graph resolves to three ordered checks:

1. an inlined overlapping ASCII-case-insensitive substring search for
   `sdk_google_phone_arm`;
2. `0x23730` kind `1` (ASCII-CI prefix) for `google/sdk_gphone_`;
3. `0x23730` kind `1` for `google/sdk_gphone64_`.

The first marker is XOR-decoded with `0xe2`, the second with `0xbc`, and the
third with `0xf2`. The inline matcher folds only ASCII `A..Z`; its mismatch
path advances the candidate input pointer and restarts, preserving overlapping
candidates. A true result short-circuits to the common mutation block. A miss
falls through to the next predicate.

Machine reconstruction of the flattened dispatcher confirms these critical
state paths:

```text
entry(non-null) -> 0x48ca0 input gate
inline byte equal at final position -> 0x48b68 mutation
inline mismatch -> 0x48c60 next candidate
first prefix true -> 0x48b68 mutation
first prefix false -> second-marker initialization
second prefix true -> 0x48b68 mutation
second prefix false -> exit
```

## Mutation

Any match raises the score to `1.0f` and appends correction `0x17`. Native
observable write order is:

```text
0x48ba4 correctionCount
0x48bb8 correction[index] = 0x17
0x48bbc score
```

`runRecoveredGooglePhoneDetector47f94` preserves this order.

## Machine-checkable evidence

```bash
python3 .omx/static-audit-20260713/analyze_google_phone_detector_47f94.py
```

The analyzer validates raw instruction anchors, reconstructs the relevant
flattened state aliases, decodes all three marker byte sequences from the SO,
checks the C++ predicate/store order, and requires targeted regression cases.
