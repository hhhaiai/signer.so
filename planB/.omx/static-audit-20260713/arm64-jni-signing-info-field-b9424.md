# ARM64 `0xb9424` JNI `PackageInfo.signingInfo` field reader

## 1. File overview

- ARM64 target: `adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so`
- ARM64 FDE: `0xb9424..0xb9cc8`, size `0x8a4`
- x86_64 counterpart: `0xae5f4..0xaece3`
- ARM64 caller edge: `0x1e44c -> 0xb9424`, inside `0x1dde0..0x1e578`
- x86_64 caller edge: `0x2324d -> 0xae5f4`, inside `0x22cf9..0x2335e`

The recovered function reads the Android API 28+ `signingInfo` object field from
a caller-supplied `android.content.pm.PackageInfo` object.  It does not allocate,
construct, or substitute a `SigningInfo` object.

## 2. Program flow

The four arguments are:

```text
status*              caller-owned uint32 status
JNIEnv                caller-supplied JNI environment
PackageInfo object    caller-supplied jobject
SigningInfo output*   caller-owned jobject output slot
```

Recovered flow:

```text
PackageInfo null
  -> status = 3
  -> output = null
  -> no JNI

GetObjectClass(PackageInfo)
  -> consume exception
  -> null/exception: status = 18

GetFieldID(class, "signingInfo",
           "Landroid/content/pm/SigningInfo;")
  -> consume exception
  -> null/exception: status = 18

GetObjectField(PackageInfo, fieldId)
  -> publish returned reference to output
  -> consume exception
  -> exception or null result: status = 28

DeleteLocalRef(PackageInfo class)
  -> if final/incoming status is nonzero, clear output
```

The temporary class local reference is owned and deleted by this helper.  A
successful non-null `SigningInfo` reference is transferred to the caller and is
not deleted inside the helper.

## 3. Key functions and evidence locations

ARM64 JNI vtable calls:

| Address | Operation |
|---:|---|
| `0xb9c30` | `GetObjectClass`, vtable `+0xf8` |
| `0xb9aec` | `GetFieldID`, vtable `+0x2f0` |
| `0xb9a1c` | `GetObjectField`, vtable `+0x2f8` |
| `0xb99d0` | `DeleteLocalRef`, vtable `+0xb8` |

Exception consumers:

```text
0xb9c50  after GetObjectClass
0xb9b0c  after GetFieldID
0xb9a40  after GetObjectField
```

Status/output evidence:

| Address | Evidence |
|---:|---|
| `0xb9bdc` | null input writes status `3` |
| `0xb9824`, `0xb9bf8` | class/field acquisition writes status `18` |
| `0xb981c` | object-field exception/null result writes status `28` |
| `0xb9a28` | returned object is first published to caller output |
| `0xb99a0..0xb99a8` | returned object is tested for null |
| `0xb99e8..0xb99f0` | final/incoming status is tested after class cleanup |
| `0xb9904` | nonzero status clears caller output |

x86_64 independently exposes the same operations at `0xaec37`, `0xaeb29`,
`0xaea69`, and `0xae9ec`; result publication is at `0xaea74`, null-result test
at `0xae9be`, status test at `0xaea33`, and output clear at `0xae946`.

## 4. Inputs, outputs, and fixed protocol data

The runtime values are caller inputs:

- `JNIEnv` handle;
- `PackageInfo` object handle;
- status storage;
- output storage;
- the actual `SigningInfo` object returned by JNI.

The following are fixed because the original SO itself fixes the Java field
contract; they are not fabricated device values:

```text
field name:       signingInfo
field descriptor: Landroid/content/pm/SigningInfo;
```

Cross-ABI XOR-once decoding:

| ABI | VMA | Length | XOR | Decoded bytes |
|---|---:|---:|---:|---|
| ARM64 | `0x145310` | 12 | `0x8b` | `signingInfo\0` |
| ARM64 | `0x145320` | 33 | `0xdc` | `Landroid/content/pm/SigningInfo;\0` |
| x86_64 | `0x13ddb0` | 12 | `0xff` | `signingInfo\0` |
| x86_64 | `0x13ddc0` | 33 | `0x2a` | `Landroid/content/pm/SigningInfo;\0` |

ARM64 uses separate acquire/release byte locks at `0x1469b0` and `0x1469b4`;
x86_64 uses the equivalent lock bytes at `0x13f040` and `0x13f042`.

## 5. Safety and ownership findings

- The helper assumes non-null `status`, output, `JNIEnv`, and callback/vtable
  storage, matching the native ABI; the portable wrapper does not invent
  replacements for invalid caller pointers.
- Incoming nonzero status does not suppress the JNI calls, but it prevents a
  successful returned reference from being published after cleanup.
- A non-null object returned together with a pending JNI exception is cleared
  from the caller output; the helper only deletes the temporary class ref.
- Field name and descriptor should remain constants in the faithful recovery.
  A separately named generic object-field adapter may accept arbitrary names,
  but must not be confused with the recovered `0xb9424` behavior.

## 6. C++ implementation and regression

Implementation symbols:

```text
RecoveredJniObjectFieldReaderOperationsB9424
runRecoveredJniSigningInfoFieldReaderB9424
recoveredJniSigningInfoFieldReaderB9424Regression
```

The direct regression covers:

- success with exact field contract and returned-reference transfer;
- incoming nonzero status with JNI still executed and output cleared;
- null PackageInfo;
- null class and class exception with conditional class cleanup;
- null field ID and field exception;
- null object-field result without exception;
- object-field exception with a non-null mock return;
- exact event order and class-ref ownership.

Dedicated verifier:

```text
.omx/static-audit-20260713/analyze_jni_signing_info_field_b9424.py
```

Existing observation-only Unidbg logs independently show the natural success
path resolving `PackageInfo.signingInfo`, returning a `SigningInfo` object, and
continuing into its methods:

```text
.omx/static-audit-20260713/unidbg-jni-order-b5828.log
```

## 7. Still unconfirmed

- The original SO has not been fault-injected on a real device for every JNI
  exception/null branch; those branches are currently established by matching
  ARM64/x86_64 static control flow and direct C++ regression.
- The parent `0x1dde0..0x1e578` orchestrator remains unknown until its remaining
  direct helpers and aggregate ownership/status flow are recovered.
