# ARM64 post-detector pair wrappers through `0x58498`

Seven entries in the `0x12a30` first-match chain are protected marker-table
initializers followed by one call to the recovered ordered string-pair helper
`0x58498`. Static instruction interpretation records the exact helper inputs
and proves that each wrapper returns the helper low bit unchanged:

| Wrapper | Pair count | Ordered pair set |
|---|---:|---|
| `0x4d9bc` | 8 | Acceleration/Gyroscope/Compass with GreatFruit, then five Google Inc. sensor pairs |
| `0x5a8e0` | 1 | TiantianVM Accelerometer / TianTian |
| `0x5c6d8` | 7 | Invensense, AOSP, STMicroelectronics, AKM and Qualcomm physical-sensor pairs |
| `0x5f900` | 3 | Goldfish accelerometer, gyroscope and orientation / Android Open Source Project |
| `0x615d8` | 2 | MPU6515 Accelerometer / InvenSense; native typo `Orientaion` / Qualcomm |
| `0x6a4e0` | 2 | Goldfish accelerometer and orientation subset |
| `0x6f758` | 2 | open-source acceleration and compass sensor pairs |

Every wrapper therefore inherits the exact `0x58498` contract: active dynamic
slot count must equal the fixed pair count, pair order is significant, all
four pointers per comparison must be non-null, and both strings require full
ASCII-only case-insensitive equality.

Source equivalents are the seven `runRecovered*Predicate*` functions backed
by their immutable marker arrays and the shared
`runRecoveredDetectorStringPairArrayEquality58498` implementation.

Reproduction:

```bash
python3 .omx/static-audit-20260713/analyze_post_detector_pair_wrappers.py
```

The analyzer interprets each flattened wrapper twice (helper result false and
true), asserts identical return propagation, validates table addresses/counts,
and checks every encoded ELF marker with its native XOR key.
