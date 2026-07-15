# ARM64 helper `0x58498` and post-detector predicate `0x6c590`

`0x6c590..0x6dbbc` constructs one protected two-string sensor descriptor:

```text
0x1446e0 XOR 0xa1 = "Genymotion Accelerometer\0"
0x144700 XOR 0x69 = "Genymobile\0"
```

It forwards the original scratch pointer, the two adjacent marker pointers,
and pair count `1` to `0x58498`.

Static execution of `0x58498..0x59658` proves the general helper contract:

1. scratch and expected-pair table must both be non-null;
2. `scratch+0x870` must exactly equal the caller pair count;
3. pair `i` reads strings at `scratch+0x70+i*0x10` and `+0x78`;
4. both actual and both expected string pointers must be non-null;
5. both strings must be complete ASCII-only case-insensitive equalities;
6. every ordered pair must match; zero pairs succeed only with valid top-level
   pointers and zero scratch count.

Therefore `0x6c590` returns true only for exactly one dynamic slot whose name
is `Genymotion Accelerometer` and whose second/vendor string is `Genymobile`,
case-insensitively. Prefixes, suffixes, count mismatches, nulls, or reversed
pair order fail.

The source equivalents are
`runRecoveredDetectorStringPairArrayEquality58498` and
`runRecoveredGenymotionSensorPredicate6c590`.

Reproduction:

```bash
python3 .omx/static-audit-20260713/analyze_post_detector_predicate_6c590.py
```
