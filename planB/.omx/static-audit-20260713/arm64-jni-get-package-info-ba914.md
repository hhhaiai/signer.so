# ARM64 JNI `PackageManager.getPackageInfo(String,int)` reader (`0xba914`)

## Scope

- ARM64 FDE: `0xba914..0xbb5a0`
- x86_64 FDE: `0xaf3e2..0xafb26`
- JNI reachable: yes
- Direct parent: certificate selector `0x1dde0..0x1e578`
- Parent calls:
  - ARM64 legacy: `0x1e3d4`, flags `0x40`
  - ARM64 API 28+: `0x1e484`, flags `0x08000000`
  - x86_64 legacy: `0x231c3`, flags `0x40`
  - x86_64 API 28+: `0x2329d`, flags `0x08000000`

The helper receives caller-supplied status storage, `JNIEnv`,
`PackageManager`, package-name `String`, flags and output storage. It calls the
Android `PackageManager.getPackageInfo(String,int)` method and transfers the
returned `PackageInfo` local reference to the caller.

## Cross-ABI fixed method contract

| ABI | VMA | length | XOR key | decoded value |
|---|---:|---:|---:|---|
| ARM64 | `0x1453b0` | 15 | `0x87` | `getPackageInfo\0` |
| ARM64 | `0x1453c0` | 54 | `0x34` | `(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;\0` |
| x86_64 | `0x13de50` | 15 | `0xcb` | `getPackageInfo\0` |
| x86_64 | `0x13de60` | 54 | `0xe9` | `(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;\0` |

Once-initialization locks:

```text
ARM64: method 0x1469c0, signature 0x1469c4
x86_64: method 0x13f048, signature 0x13f04a
```

Executable proof:

```text
.omx/static-audit-20260713/analyze_jni_get_package_info_ba914.py
```

## Recovered inputs and call forwarding

ARM64 arguments:

```text
x0 status*
x1 JNIEnv
x2 PackageManager
x3 packageName String
w4 flags
x5 output PackageInfo*
```

x86_64 arguments:

```text
rdi status*
rsi JNIEnv
rdx PackageManager
rcx packageName String
r8d flags
r9 output PackageInfo*
```

The parent forwards two exact flag values:

```text
API <= 27: 0x00000040
API >= 28: 0x08000000
```

## Recovered JNI/status/ownership flow

1. Null caller-supplied `PackageManager` or package-name `String` writes status
   `3`, clears output and performs no JNI call.
2. `GetObjectClass(PackageManager)` is followed by exception consumption. Null
   class or exception writes status `18`.
3. `GetMethodID(class,"getPackageInfo",signature)` is followed by exception
   consumption. Null method ID or exception writes status `18`.
4. `CallObjectMethod(PackageManager,methodId,packageName,flags)` publishes the
   returned `PackageInfo` before the third exception consume.
5. Call exception or null returned `PackageInfo` writes status `35` (`0x23`).
6. The temporary `PackageManager` class local reference is deleted on every
   acquired-class path.
7. A successful `PackageInfo` local reference is transferred to the caller.
   Incoming nonzero status does not suppress JNI, but clears the otherwise
   valid output after class cleanup.

JNI table offsets are identical on both ABIs:

```text
GetObjectClass   +0xf8
GetMethodID      +0x108
CallObjectMethod +0x110
DeleteLocalRef   +0xb8
```

## Key evidence addresses

| Operation | ARM64 | x86_64 |
|---|---:|---:|
| input null gates | `0xba938`, `0xba96c` | `0xaf43b`, `0xaf45e` |
| GetObjectClass | `0xbb1d0` | `0xaf94c` |
| class exception consume | `0xbb1f0` | `0xaf962` |
| GetMethodID | `0xbad28` | `0xaf6c9` |
| method exception consume | `0xbad48` | `0xaf6df` |
| CallObjectMethod | `0xbae70` | `0xaf796` |
| result publication | `0xbae7c` | `0xaf7a2` |
| call exception consume | `0xbae94` | `0xaf7b2` |
| null-result check | `0xbb390..0xbb398` | `0xafa54..0xafa59` |
| DeleteLocalRef | `0xbb4a0` | `0xafab0` |
| final status check | `0xbb4c0..0xbb540` | `0xafb01` |
| output clear | `0xbb1b8` | `0xaf92f` |
| status 3 | `0xbb004` | `0xaf886` |
| status 18 | `0xbaf80`, `0xbafc4` | `0xaf817`, `0xaf863` |
| status 35 | `0xbacf4` | `0xaf69c` |

## C++ evidence

- Operations table: `RecoveredJniGetPackageInfoOperationsBa914`
- Implementation: `runRecoveredJniGetPackageInfoBa914`
- Regression: `recoveredJniGetPackageInfoBa914Regression`
- Implementation location:
  `native-reimplementation/recovered_primitives.cpp:10099..10147`
- Regression location:
  `native-reimplementation/recovered_primitives.cpp:10241..10384`

The regression covers both flag values, all argument forwarding, incoming
status `0x55`, null `PackageManager`, null package name, class null/exception,
method null/exception, call null/exception, status `35`, event order,
class-reference cleanup and returned-reference transfer.

## Isolated dynamic corroboration

Existing local Unidbg JNI-verbose runs observed both natural parent branches
without modifying registers, branches, return values, JNI objects, status or
target bytes.

Legacy API 18:

```text
PackageManager.getPackageInfo("local.qbdi.adjustreference", 0x40)
CallObjectMethod return PC: libsigner.so+0xbae78
```

API 28+ profile:

```text
PackageManager.getPackageInfo("com.example.structured.device", 0x08000000)
CallObjectMethod return PC: libsigner.so+0xbae78
```

Logs:

```text
.omx/static-audit-20260713/current-337-51-b8830-legacy-api18-jni-trace-attempt-1.log
.omx/static-audit-20260713/unidbg-jni-order-b5828.log
```

## Verification result and boundary

```text
cross-ABI PackageManager.getPackageInfo constants: PASS
cross-ABI getPackageInfo JNI/status/ownership flow: PASS
C++ regression and recovered JNI coverage: PASS
build-and-test / 15 original-SO oracle vectors: PASS
ASan+UBSan: PASS (LeakSanitizer disabled on macOS)
frozen recovered backend exact match: PASS
offline Maven recovered integration: 21/21 PASS
offline Maven original integration: 1/1 PASS
all static analyzers: 145/145 PASS
```

Formal totals are now `338 recovered / 50 unknown`; the JNI-reachable subset is
`289 recovered / 32 unknown`. Every direct FDE callee of parent `0x1dde0` is
now recovered, but the parent itself remains unknown until its API-dependent
branching, `Signature[]` element selection, status short-circuit and complete
local-reference cleanup state machine receive independent C++ and regression
coverage.
