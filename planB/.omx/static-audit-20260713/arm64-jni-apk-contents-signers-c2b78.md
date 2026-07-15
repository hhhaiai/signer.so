# ARM64 JNI `SigningInfo.getApkContentsSigners()` reader (`0xc2b78`)

## Scope

- ARM64 FDE: `0xc2b78..0xc375c`
- x86_64 FDE: `0xb3ff9..0xb46d8`
- JNI reachable: yes
- Direct parent:
  - ARM64 `0x1dde0..0x1e578`, call at `0x1e4c8`
  - x86_64 `0x22cf9..0x2335e`, call at `0x232df`

## Cross-ABI constants

| ABI | VMA | length | XOR key | decoded value |
|---|---:|---:|---:|---|
| ARM64 | `0x1455a0` | 22 | `0x5a` | `getApkContentsSigners\0` |
| ARM64 | `0x1455c0` | 34 | `0x0c` | `()[Landroid/content/pm/Signature;\0` |
| x86_64 | `0x13e040` | 22 | `0x94` | `getApkContentsSigners\0` |
| x86_64 | `0x13e060` | 34 | `0x49` | `()[Landroid/content/pm/Signature;\0` |

The executable proof is
`.omx/static-audit-20260713/analyze_jni_apk_contents_signers_c2b78.py`.

## Recovered JNI/status/ownership flow

1. A null caller-supplied `SigningInfo` writes status `3`, clears the output
   and performs no JNI operation.
2. `GetObjectClass(SigningInfo)` is followed by an exception consume. A null
   class or exception writes status `18`.
3. `GetMethodID("getApkContentsSigners",
   "()[Landroid/content/pm/Signature;")` is followed by an exception consume.
   A null method or exception writes status `18`.
4. `CallObjectMethod(SigningInfo, method)` publishes the returned local
   reference before the third exception consume. A call exception or null
   result writes status `28`.
5. The temporary `SigningInfo` class local reference is deleted on every path
   after successful acquisition.
6. The returned `Signature[]` local reference is transferred to the caller
   only when final status is zero. Incoming nonzero status does not suppress
   the JNI sequence, but clears the final output after class cleanup.

JNI vtable evidence is `+0xf8` (`GetObjectClass`), `+0x108`
(`GetMethodID`), `+0x110` (`CallObjectMethod`) and `+0xb8`
(`DeleteLocalRef`) on both ABIs.

## C++ evidence

- Operations alias: `RecoveredJniApkContentsSignersOperationsC2b78`
- Implementation: `runRecoveredJniApkContentsSignersC2b78`
- Regression: `recoveredJniApkContentsSignersC2b78Regression`
- Current source location:
  `native-reimplementation/recovered_primitives.cpp:7239..7403`
- Coverage generator:
  `.omx/static-audit-20260713/generate_arm64_function_inventory.py`
- Coverage row:
  `.omx/static-audit-20260713/arm64-function-inventory.csv`

The regression covers success, exact method contract, argument forwarding,
incoming nonzero status, null `SigningInfo`, class null/exception, method
null/exception, call null/exception, event ordering, class-ref cleanup and
returned-reference transfer.

## Verification result

```text
cross-ABI SigningInfo APK-content-signers constants: PASS
cross-ABI APK-content-signers JNI/status/ownership flow: PASS
C++ regression and recovered JNI coverage: PASS
```

The current formal totals after the subsequent `0xba914` closure are
`338 recovered / 50 unknown`; the JNI-reachable subset is
`289 recovered / 32 unknown`.

## Remaining dynamic uncertainty

There is not yet a dedicated observation-only original-SO hook for this exact
helper. Function-level closure is based on cross-ABI static proof and direct
C++ regression. Every direct FDE callee of parent `0x1dde0` is now recovered,
but the parent remains unknown until API-level branch selection and all
local-reference cleanup paths are independently recovered and tested.
