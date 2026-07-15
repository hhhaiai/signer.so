# ARM64 `0x490f0..0x4afd4` iTools detector

## Input fields

The four fanout arguments are scratch, score, correction array and correction
count. `0x49114..0x49124` requires scratch and the correction array. The
flattened body then checks these scratch fields in order:

```text
scratch+0x08
scratch+0x18
scratch+0x20
```

Null fields are skipped.

## Predicate

The process-global marker at `0x1443e8` decodes with XOR `0x36` to:

```text
itools\0
```

Each of the three inlined matchers advances the candidate and marker pointers
in lockstep. The marker boundary is the last non-NUL byte at `0x1443ee`.
Multiple repeated blocks fold only ASCII `A..Z` before comparing bytes. There
is no mismatch path that advances only the candidate and restarts the marker,
so this is full-string equality, not substring matching. The terminating
checks require both strings to finish together; `prefix-itools` and
`itools-suffix` are rejected, while case variants such as `ITOOLS` match.

## Mutation

The first matching field short-circuits to the common action:

```text
0x4ab24 correctionCount = count + 1
0x4ab38 correction[count] = 0x18
0x4ab40 score = score + (1 - score)
```

The direct C++ implementation is `runRecoveredItoolsDetector490f0`.

## Machine-checkable evidence

```bash
python3 .omx/static-audit-20260713/analyze_itools_detector_490f0.py
```

The analyzer checks all three field loads, marker decoding, repeated ASCII
folding blocks, three lockstep pointer pairs, marker-boundary checks, native
mutation order, direct C++ implementation and targeted prefix/suffix tests.
