# ARM64 `0x352d4..0x36bfc` build-identity predicate

## Inputs and marker groups

The predicate receives the detector scratch object and checks three fields in
native short-circuit order:

```text
scratch+0x10 -> android / android-x86
scratch+0x18 -> android sdk built for x86 / android sdk built for x86_64
scratch+0x20 -> generic_x86 / generic_x86_64
```

The six writable global strings are published by one-time XOR decoders.  Their
plaintext bytes and pointer pairs at `0x146758`, `0x146768` and `0x146778` are
validated directly against the ELF image by the static analyzer.

## Helper `0x36bfc`

`0x36bfc` receives `(value, length, twoMarkerTable)`.  A zero length or null
table returns false.  Otherwise it compares the caller-supplied byte range to
each of the two markers using ASCII-only `A..Z` folding and returns on the first
complete equal-length match.  The helper deliberately obeys the supplied
length; the `0x352d4` caller supplies `strlen(value)`, producing full-string
ASCII-CI equality for the detector.

Null scratch fields are skipped.  A match short-circuits later fields.  This
means a marker placed in the wrong field does not match; for example
`scratch+0x18 = android-x86` is rejected.

The direct implementations are `runRecoveredTwoMarkerEquality36bfc` and
`runRecoveredBuildIdentityPredicate352d4`.

## Reproduction

```bash
python3 .omx/static-audit-20260713/analyze_detector_predicate_352d4.py
```

The analyzer interprets both flattened ARM64 FDEs, checks marker decoding,
field order, helper call order, exact/prefix cases, first-hit short circuit and
the corresponding C++ implementation/regression.
