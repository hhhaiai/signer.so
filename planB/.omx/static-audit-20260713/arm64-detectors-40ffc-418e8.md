# ARM64 detector stages `0x40ffc` and `0x418e8`

Both functions use the common detector fanout ABI:

```text
x0 = detector scratch
x1 = float score pointer
x2 = uint16 correction array
x3 = uint64 correction count pointer
```

They guard the scratch and correction-array pointers, read the string pointer
at scratch `+0x18`, and return without mutation when the field is null.

## Matcher semantics

The flattened control flow contains two cursor pairs:

- the current candidate/marker cursors advance together after a matching byte;
- a separately retained candidate-start cursor advances by exactly one byte on
  mismatch, while the marker cursor is reset to its first byte.

That restart rule proves an overlapping substring scan rather than full-string
equality. Bytes are first compared directly, then folded only when needed with
the native ASCII `A..Z -> a..z` sequence (`sub #0x5b`, range check, `orr #0x20`).
The success transition is reachable only after the last marker byte matches.

Source-level equivalent:

```cpp
for (const char* start = haystack; *start != '\0'; ++start) {
    compare marker at start with ASCII case folding;
    if (the complete marker matched) return true;
}
return false;
```

## `0x40ffc..0x418d8`

- input: `scratch->fixedString18`
- encoded marker vaddr: `0x144298`
- XOR byte: `0x90`
- decoded marker: `google_sdk\0`
- on match: append correction `0x0d`
- score: `score + (1.0f - score)`, preserving the native FP operation order
- store order: correction, count, score

## `0x418e8..0x421cc`

- input: `scratch->fixedString18`
- encoded marker vaddr: `0x143618`
- XOR byte: `0x68`
- decoded marker: `emulator\0`
- on match: append correction `0x0e`
- score: `score + (1.0f - score)`, preserving the native FP operation order
- store order: count, correction, score

Direct C++:

```text
recoveredAsciiCaseInsensitiveContains40ffc
runRecoveredGoogleSdkSubstringDetector40ffc
runRecoveredEmulatorSubstringDetector418e8
```

Repeatable static evidence check:

```bash
python3 .omx/static-audit-20260713/analyze_detectors_40ffc_418e8.py
```
