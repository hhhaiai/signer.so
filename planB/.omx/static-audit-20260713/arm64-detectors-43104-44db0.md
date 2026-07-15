# ARM64 detector stages `0x43104` through `0x44db0`

These four fanout stages use the same flattened, overlapping ASCII
case-insensitive substring loop already recovered for `0x40ffc/0x418e8`.
Each function retains the candidate start separately, advances it by one on a
mismatch, advances candidate and marker cursors together on a match, and emits
its correction only after the final marker byte matches.

| Function | Scratch field | Encoded marker | XOR | Plaintext | Correction |
|---|---:|---:|---:|---|---:|
| `0x43104..0x43998` | `+0x40` | `0x1434e8` | `0x30` | `goldfish` | `0x10` |
| `0x439a8..0x442dc` | `+0x40` | `0x143634` | `0x31` | `vbox86` | `0x11` |
| `0x442ec..0x44c28` | `+0x20` | `0x143634` | `0x31` | `vbox86` | `0x12` |
| `0x44db0..0x456a8` | `+0x40` | `0x1442f0` | `0x28` | `android_x86` | `0x14` |

Every match reaches the same final state:

```cpp
index = *correctionCount;
*correctionCount = index + 1;
corrections[index] = function_specific_code;
*score = *score + (1.0f - *score);
```

The direct C++ also preserves the native store order. `0x439a8` stores count,
correction, then score. `0x43104`, `0x442ec`, and `0x44db0` store correction,
count, then score.

The structure model now names the pointer at scratch `+0x40` as
`fixedString40`; the following word remains opaque, preserving all later field
offsets.

Repeatable evidence check:

```bash
python3 .omx/static-audit-20260713/analyze_detectors_43104_44db0.py
```
