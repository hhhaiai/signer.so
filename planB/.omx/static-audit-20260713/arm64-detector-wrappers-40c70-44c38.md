# ARM64 detector wrappers `0x40c70` and `0x44c38`

## `0x40c70..0x40fec`: generic substring detector

Inputs follow the common fanout contract:

```text
x0 = detector scratch
x1 = float score pointer
x2 = uint16 correction array
x3 = uint64 correction count pointer
```

The function checks `x0` and `x2`, reads the string pointer at scratch `+0x30`,
and skips the detector when any required value is null. It publishes a global
eight-byte marker once using acquire-byte CAS and XOR `0xdf`. The encoded bytes
at vaddr `0x143718` decode exactly to `generic\0`.

It invokes the recovered case-sensitive substring predicate `0x127a78` with:

```text
contains(scratch->fixedString30, "generic")
```

On false, there is no externally visible mutation. On true:

```cpp
index = *correctionCount;
*correctionCount = index + 1;
corrections[index] = 0x0b;
*score = *score + (1.0f - *score) * 0.3f;
```

The `0.3f` constant is stored at vaddr/file offset `0x2f64` as
`9a99993e`. Mutation order and correction code are visible at
`0x40f94..0x40fbc`.

## `0x44c38..0x44da0`: predicate wrapper

This function checks the scratch and correction-array pointers, calls the
separately inventoried predicate `0x352d4` once with the scratch pointer, and
does nothing on a false low-bit result. On true it performs:

```cpp
index = *correctionCount;
*correctionCount = index + 1;
corrections[index] = 0x13;
*score = *score + (1.0f - *score); // 1.0f
```

The child predicate remains an independent recovery item; the wrapper's
argument forwarding, branch, correction, score, and mutation order are fully
closed through a callback boundary.

Direct C++:

```text
runRecoveredGenericSubstringDetector40c70
runRecoveredDetectorWrapper44c38
```

Repeatable evidence check:

```bash
python3 .omx/static-audit-20260713/analyze_detector_wrappers_40c70_44c38.py
```
