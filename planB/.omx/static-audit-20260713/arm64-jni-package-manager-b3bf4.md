# ARM64 JNI `Context.getPackageManager()` reader (`0xb3bf4`)

## Scope

- ARM64 FDE: `0xb3bf4..0xb479c`
- x86_64 FDE: `0xab508..0xabbd8`
- JNI reachable: yes
- Direct parent:
  - ARM64 `0x1dde0..0x1e578`, call at `0x1e418`
  - x86_64 `0x22cf9..0x2335e`, call at `0x23208`

## Cross-ABI constants

| ABI | VMA | length | XOR key | decoded value |
|---|---:|---:|---:|---|
| ARM64 | `0x145140` | 18 | `0x42` | `getPackageManager\0` |
| ARM64 | `0x145160` | 38 | `0x03` | `()Landroid/content/pm/PackageManager;\0` |
| x86_64 | `0x13dbe0` | 18 | `0xd3` | `getPackageManager\0` |
| x86_64 | `0x13dc00` | 38 | `0xf2` | `()Landroid/content/pm/PackageManager;\0` |

The executable proof is
`.omx/static-audit-20260713/analyze_jni_package_manager_b3bf4.py`.

## Recovered JNI/status/ownership flow

1. A null caller-supplied `Context` writes status `3`, clears the output and
   performs no JNI operation.
2. `GetObjectClass(Context)` is followed by an exception consume.  A null
   class or exception writes status `18`.
3. `GetMethodID("getPackageManager",
   "()Landroid/content/pm/PackageManager;")` is followed by an exception
   consume.  A null method or exception writes status `18`.
4. `CallObjectMethod(Context, method)` publishes the returned local reference
   before the third exception consume.  A call exception or null result writes
   status `18`; this helper does not use status `28`.
5. The temporary `Context` class local reference is deleted on every path
   after successful acquisition.
6. The returned `PackageManager` local reference is transferred to the caller
   only when final status is zero.  Incoming nonzero status does not suppress
   the JNI sequence, but clears the final output after class cleanup.

JNI vtable evidence is `+0xf8` (`GetObjectClass`), `+0x108`
(`GetMethodID`), `+0x110` (`CallObjectMethod`) and `+0xb8`
(`DeleteLocalRef`) on both ABIs.

## C++ evidence

- Operations alias: `RecoveredJniPackageManagerOperationsB3bf4`
- Implementation: `runRecoveredJniPackageManagerB3bf4`
- Regression: `recoveredJniPackageManagerB3bf4Regression`
- Current source location:
  `native-reimplementation/recovered_primitives.cpp:7061..7225`
- Coverage generator:
  `.omx/static-audit-20260713/generate_arm64_function_inventory.py`
- Coverage row:
  `.omx/static-audit-20260713/arm64-function-inventory.csv`

The regression covers success, exact method contract, argument forwarding,
incoming nonzero status, null Context, class null/exception, method
null/exception, call null/exception, event ordering, class-ref cleanup and
returned-reference transfer.

## Verification result

```text
cross-ABI Context.getPackageManager constants: PASS
cross-ABI getPackageManager JNI/status/ownership flow: PASS
C++ regression and recovered JNI coverage: PASS
```

The current formal totals after the subsequent `0xba914` closure are
`338 recovered / 50 unknown`; the JNI-reachable subset is
`289 recovered / 32 unknown`.

## Remaining dynamic uncertainty

There is not yet a dedicated observation-only original-SO hook for this exact
helper. Function-level closure is based on cross-ABI static proof and direct
C++ regression. Every direct FDE callee of parent `0x1dde0` is now recovered,
but the parent remains unknown until the API-dependent certificate
selection/status/cleanup flow is reconstructed and independently tested.
