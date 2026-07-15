# ARM64 detector stages `0x456b8` and `0x47f94`

## `0x456b8..0x47778`

- candidate is `scratch+0x00` (`0x46f2c`, `0x46f3c`), not `scratch+0x28`;
- eleven decoded descriptor strings are passed to `0x42eb0`;
- kind vector is `{0,0,0,0,0,3,0,0,3,3,1}`;
- recovered kind semantics are ASCII-CI equality, ASCII-CI substring, and
  ASCII-CI prefix;
- first match raises score to `1.0f` and appends correction `0x15`.

Descriptors, in native order:

```text
sdk_x86_64
sdk
google_sdk
sdk_x86
vbox86p
sdk_google
sdk_google_phone_x86_64
sdk_google_phone_arm64
sdk_gphone64_arm64
vbox
sdk_gphone_
```

## `0x47f94..0x490e0`

- candidate is `scratch+0x30` (`0x48cb8`, `0x48f98`);
- first predicate is an inlined overlapping ASCII-CI search for
  `sdk_google_phone_arm`;
- after a miss, kind one is called in order with:
  - `google/sdk_gphone_`;
  - `google/sdk_gphone64_`;
- kind one is the `0x12ad00` ASCII-CI prefix predicate;
- any match appends correction `0x17` and raises score to `1.0f`.

Evidence:

```text
.omx/static-audit-20260713/analyze_detectors_456b8_47f94.py
.omx/static-audit-20260713/disasm-456b8-47778.txt
.omx/static-audit-20260713/disasm-47f94-490e0.txt
native-reimplementation/recovered_primitives.cpp
```
