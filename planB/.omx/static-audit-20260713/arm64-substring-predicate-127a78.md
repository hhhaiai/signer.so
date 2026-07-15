# ARM64 `0x127a78..0x128038` substring predicate

The function is a call-free, case-sensitive, naive substring search over two
NUL-terminated byte strings.

## Contract

```cpp
bool contains(const char* haystack, const char* needle);
```

- null haystack or null needle returns false (`0x127a94..0x127b2c`);
- an empty needle returns true;
- a nonempty needle longer than the remaining haystack cannot match;
- scanning advances one haystack start byte at a time, so overlaps are tested;
- bytes are compared exactly; there is no ASCII folding block;
- the first complete needle match returns true, exhaustion returns false.

The two length scans and subtraction at `0x127e60..0x127fac` establish the
remaining-window boundary. Candidate and needle bytes are loaded at
`0x127e20..0x127e54`; equal-byte progression and the outer one-byte advance
are visible at `0x127dec..0x127e1c`. Result one is written from `0x127f54`,
result zero from `0x127de4`, and the low bit is returned at
`0x128028..0x128034`.

The detector callers use this helper for decoded fragments such as `generic`,
which are searched inside longer build/property strings.

Direct C++ is `runRecoveredSubstringPredicate127a78`. Regression covers null
inputs, empty strings, exact/prefix/middle/suffix matches, case sensitivity,
longer needles, overlapping candidates, and absence.

Repeatable evidence check:

```bash
python3 .omx/static-audit-20260713/analyze_substring_predicate_127a78.py
```
