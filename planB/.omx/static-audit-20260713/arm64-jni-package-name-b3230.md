# ARM64 JNI `Context.getPackageName()` reader (`0xb3230`)

## Scope

- ARM64 FDE: `0xb3230..0xb3bf4`
- x86_64 FDE: `0xaae64..0xab508`
- JNI reachable: yes
- Direct parent observed in the package/signing-certificate orchestration:
  - ARM64 `0x1dde0..0x1e578`, call at `0x1de44`
  - x86_64 `0x22cf9..0x2335e`, call at `0x22d6f`

## Cross-ABI constants

| ABI | VMA | length | XOR key | decoded value |
|---|---:|---:|---:|---|
| ARM64 | `0x145128` | 15 | `0xf5` | `getPackageName\0` |
| ARM64 | `0x144af0` | 21 | `0x47` | `()Ljava/lang/String;\0` |
| x86_64 | `0x13dbc8` | 15 | `0x81` | `getPackageName\0` |
| x86_64 | `0x13d590` | 21 | `0x2a` | `()Ljava/lang/String;\0` |

The decoding and all control-flow checks are executable assertions in
`analyze_jni_package_name_b3230.py`.

## Recovered JNI flow

1. Null caller-supplied `Context` writes status `3`, clears the output, and
   performs no JNI operation.
2. `GetObjectClass(Context)` is followed by an exception consume.  A null
   class or exception writes status `18`.
3. `GetMethodID("getPackageName", "()Ljava/lang/String;")` is followed by an
   exception consume.  A null method or exception writes status `18`.
4. `CallObjectMethod(Context, method)` publishes the returned local reference
   before the third exception consume.  An exception or null result writes
   status `28`.
5. The temporary `Context` class local reference is deleted on every path on
   which it was acquired.
6. The returned `String` local reference is transferred to the caller only
   when final status is zero.  A pre-existing nonzero status does not suppress
   the JNI calls, but the final output is cleared after class cleanup.

ARM64 JNI vtable evidence includes `+0xf8` (`GetObjectClass`), `+0x108`
(`GetMethodID`), `+0x110` (`CallObjectMethod`), and `+0xb8`
(`DeleteLocalRef`).  The x86_64 implementation uses the same offsets and
ordering.

## C++ evidence

- Interface alias: `RecoveredJniPackageNameOperationsB3230`
- Implementation: `runRecoveredJniPackageNameB3230`
- Regression: `recoveredJniPackageNameB3230Regression`
- Current source location: `native-reimplementation/recovered_primitives.cpp`
  around lines `6873..7047`
- Coverage generator entry:
  `.omx/static-audit-20260713/generate_arm64_function_inventory.py`
- Machine-readable coverage row:
  `.omx/static-audit-20260713/arm64-function-inventory.csv`

The regression covers success, caller forwarding, the exact method contract,
incoming nonzero status, null input, class null/exception, method
null/exception, call null/exception, event order, class-local-reference
cleanup, and returned-reference transfer.

## Verification result

```text
cross-ABI Context.getPackageName constants: PASS
cross-ABI getPackageName JNI/status/ownership flow: PASS
C++ regression and recovered JNI coverage: PASS
```

At the time of this closure the formal totals changed from `332/56` to
`333 recovered / 55 unknown`; JNI-reachable coverage changed from `283/38` to
`284 recovered / 37 unknown`.  The subsequent `0xc4064` closure advances the
matrix to `334/54`, and the later `0xb3bf4` closure advances the current
matrix to `335/53`, with JNI-reachable coverage at `286/35`.

## Remaining dynamic uncertainty

No dedicated observation-only original-SO hook currently records this helper's
entry/status/output/cleanup tuple.  The current evidence for `0xb3230` is
cross-ABI static proof plus direct C++ regression.  A future isolated Unidbg
test should observe the existing execution without modifying registers,
branches, return values, JNI objects, or target bytes.
