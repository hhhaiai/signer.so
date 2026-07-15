# ARM64 `0x4b020..0x4d9ac` Apple/iPhone detector

The final ARM64 `0x7ba5c` fanout stage uses the common four-argument detector
ABI.  The entry gate checks the correction array in `x2` at `0x4b044` and the
scratch object in `x0` at `0x4b050`; `x1` is saved as the score pointer and
`x3` as the correction-count pointer.

## Inputs and markers

- `0x4d544` loads `scratch+0x10`.
- `0x4d6ac` loads `scratch+0x20` only after the first field is null or all of
  its searches miss.
- `0x1443f0 XOR 0x83` decodes to `apple\0`.
- `0x1443f8 XOR 0xc6` decodes to `iphone\0`.

The repeated lockstep byte blocks fold only ASCII `A..Z` with `| 0x20`.  A
static interpreter over the saved ARM64 instructions proves that both fields
accept both markers as overlapping case-insensitive substrings:

- `prefix-APPLE-suffix` in `scratch+0x10` matches and short-circuits before
  `scratch+0x20` is read.
- `prefix-iPhOnE-tail` in either field matches.
- `app` and `iphon` do not match.
- null fields are skipped, and two null fields are a no-op.

This rules out full equality, prefix-only and suffix-only interpretations.

## Mutation

The common hit block begins at `0x4caac`:

1. `0x4caf8` stores `correctionCount + 1`.
2. `0x4cb08` stores the score update, which is exactly `1.0f`.
3. `0x4cb2c` stores correction `0x1c` at the old count index.

The recovered source is
`runRecoveredAppleIphoneDetector4b020` in
`native-reimplementation/recovered_primitives.cpp`.

## Reproduction

```bash
python3 .omx/static-audit-20260713/analyze_apple_iphone_detector_4b020.py
```

Expected output:

```text
arm64 apple/iphone detector 0x4b020 evidence: PASS
```
