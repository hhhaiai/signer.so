# ARM64 JNI legacy `PackageInfo.signatures` field reader (`0xb8830`)

## Scope

- ARM64 FDE: `0xb8830..0xb9424`
- x86_64 FDE: `0xadf2e..0xae5f4`
- JNI reachable: yes
- Direct parent:
  - ARM64 `0x1dde0..0x1e578`, call at `0x1e378`
  - x86_64 `0x22cf9..0x2335e`, call at `0x23170`

This is the API 27-and-lower certificate-array path. The caller passes a
`PackageInfo`; the helper reads its legacy `signatures` field and transfers the
returned `Signature[]` local reference.

## Cross-ABI fixed field contract

| ABI | VMA | length | XOR key | decoded value |
|---|---:|---:|---:|---|
| ARM64 | `0x1452e0` | 11 | `0x1f` | `signatures\0` |
| ARM64 | `0x1452f0` | 32 | `0x0b` | `[Landroid/content/pm/Signature;\0` |
| x86_64 | `0x13dd80` | 11 | `0x40` | `signatures\0` |
| x86_64 | `0x13dd90` | 32 | `0x5c` | `[Landroid/content/pm/Signature;\0` |

The executable static proof is:

```text
.omx/static-audit-20260713/analyze_jni_legacy_signatures_field_b8830.py
```

## Recovered JNI/status/ownership flow

1. Null caller-supplied `PackageInfo` writes status `3`, clears output and
   performs no JNI call.
2. `GetObjectClass(PackageInfo)` is followed by exception consumption. Null
   class or exception writes status `18`.
3. `GetFieldID(class,"signatures","[Landroid/content/pm/Signature;")` is
   followed by exception consumption. Null field ID or exception writes `18`.
4. `GetObjectField(PackageInfo,fieldId)` publishes the returned reference before
   the third exception consume. Exception or null result writes status `28`.
5. The temporary `PackageInfo` class local reference is deleted on every path
   after acquisition.
6. A successful `Signature[]` local reference is transferred to the caller.
   Incoming nonzero status does not suppress JNI, but clears output after class
   cleanup.

JNI table offsets are identical on both ABIs:

```text
GetObjectClass  +0xf8
GetFieldID      +0x2f0
GetObjectField  +0x2f8
DeleteLocalRef  +0xb8
```

## Key evidence addresses

| Operation | ARM64 | x86_64 |
|---|---:|---:|
| null input gate | `0xb8880` | `0xadf8c` |
| GetObjectClass | `0xb8f44` | `0xae318` |
| GetFieldID | `0xb9258` | `0xae4bd` |
| GetObjectField | `0xb8d34` | `0xae255` |
| result publication | `0xb8d40` | `0xae260` |
| DeleteLocalRef | `0xb90e8` | `0xae3fc` |
| final status check | `0xb9108..0xb9120` | `0xae443` |
| output clear | `0xb93cc` | `0xae5ac` |
| status 3 | `0xb8d0c` | `0xae22b` |
| status 18 | `0xb8f18`, `0xb93d8` | `0xae2f9`, `0xae5bd` |
| status 28 | `0xb8c08` | `0xae1dc` |

## C++ evidence

- Operations alias: `RecoveredJniLegacySignaturesFieldOperationsB8830`
- Implementation: `runRecoveredJniLegacySignaturesFieldReaderB8830`
- Regression: `recoveredJniLegacySignaturesFieldReaderB8830Regression`
- Implementation location:
  `native-reimplementation/recovered_primitives.cpp:9641..9688`
- Regression location:
  `native-reimplementation/recovered_primitives.cpp:9833..9953`

The regression covers success, exact field contract, argument forwarding,
incoming nonzero status, null PackageInfo, class null/exception, field-ID
null/exception, result null/exception, event order, class-ref cleanup and
returned-reference transfer.

## Isolated dynamic corroboration

The local API 18 Unidbg run enabled JNI verbose without modifying registers,
returns, branches, JNI objects, status, or target bytes. Two natural signing
paths recorded:

```text
PackageManager.getPackageInfo("local.qbdi.adjustreference", 0x40)
GetFieldID(PackageInfo.signatures, [Landroid/content/pm/Signature;)
GetObjectField(... => [android.content.pm.Signature@...])
GetObjectArrayElement(Signature[], 0)
```

The native return PCs match the static helper:

```text
GetFieldID return:    libsigner.so+0xb9260
GetObjectField return: libsigner.so+0xb8d3c
```

Trace log:

```text
.omx/static-audit-20260713/current-337-51-b8830-legacy-api18-jni-trace-attempt-1.log
```

After recording the behavior, the traced fork ended with the known macOS
Unicorn teardown `Abort trap: 6` / exit 134. Therefore the trace is valid as
observation evidence, but the Maven invocation is not reported as a passing
test.

## Current boundary

Formal totals are now `338 recovered / 50 unknown`; JNI reachable totals are
`289 recovered / 32 unknown`. The subsequent `0xba914` closure means every
direct FDE callee of parent `0x1dde0` is recovered. The parent itself remains
unknown until its complete API-dependent selection/status/cleanup state machine
has independent C++ and regression coverage.
