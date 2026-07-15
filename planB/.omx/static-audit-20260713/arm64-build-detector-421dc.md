# ARM64 build-fingerprint detector `0x421dc..0x42eb0`

The function uses the common detector fanout arguments, guards the scratch and
correction-array pointers, and reads the candidate string from scratch `+0x18`.

Four process-global encoded strings are published once and placed into a local
four-pointer descriptor array:

```text
vaddr 0x144050 XOR 0x42 -> android sdk built for x86
vaddr 0x1442b0 XOR 0x09 -> android sdk built for arm64
vaddr 0x1442d0 XOR 0x39 -> android sdk built for armv7
vaddr 0x144070 XOR 0x99 -> android sdk built for x86_64
```

At `0x42734..0x42774`, the function builds:

```text
x0 = scratch->fixedString18
x1 = four descriptor pointers
x2 = four uint32 zeros
x3 = 4
call 0x42eb0
```

The fixed zero kind is important. Static interpretation of `0x23730` shows
that kind zero stays inside the dispatcher and performs full-string
ASCII-case-insensitive equality. It does not route to `0x127a78`; that helper
belongs to another descriptor kind. Prefixes and suffixes around a marker are
therefore rejected. Other `0x23730` kinds remain separately inventoried.

If any marker is found, the stage performs the native mutation order:

```cpp
*score = *score + (1.0f - *score);
index = *correctionCount;
*correctionCount = index + 1;
corrections[index] = 0x0f;
```

Direct C++:

```text
runRecoveredDescriptorPredicate23730Kind0
runRecoveredBuildFingerprintDetector421dc
```

Repeatable evidence check:

```bash
python3 .omx/static-audit-20260713/analyze_build_detector_421dc.py
```
