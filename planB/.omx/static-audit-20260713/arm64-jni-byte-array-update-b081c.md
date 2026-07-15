# JNI `update(byte[])` void-method helper `0xb081c`

## Scope

ARM64 FDE:

```text
0xb081c..0xb0f38
```

x86_64 equivalent FDE:

```text
0xa91a3..0xa9783
```

The sole recovered caller edges are:

```text
ARM64  0x1ee24 -> 0xb081c  in FDE 0x1e578..0x1f058
x86_64 0x23aa7 -> 0xa91a3 in FDE 0x2335e..0x23d51
```

The caller forwards `status`, `JNIEnv`, the Java object and the input
`jbyteArray` unchanged.

## Decoded protocol constants

| ABI | VMA | file offset | XOR key | plaintext |
|---|---:|---:|---:|---|
| ARM64 | `0x145048` | `0x13d048` | `0xa5` | `update\0` |
| ARM64 | `0x145050` | `0x13d050` | `0x7b` | `([B)V\0` |
| x86_64 | `0x13dae8` | `0x135ae8` | `0x55` | `update\0` |
| x86_64 | `0x13daf0` | `0x135af0` | `0x5e` | `([B)V\0` |

Both ABIs use two independent acquire/release once-lock protocols before the
decoded strings are passed to `GetMethodID`.

## JNI flow

| operation | ARM64 | x86_64 | JNI table offset |
|---|---:|---:|---:|
| `GetObjectClass` | `0xb0ba8` | `0xa9456` | `+0xf8` |
| exception consume | `0xb0bb8` | `0xa946f` | helper call |
| `GetMethodID` | `0xb0e34` | `0xa9672` | `+0x108` |
| exception consume | `0xb0e40` | `0xa9688` | helper call |
| `CallVoidMethod` | `0xb0ea4` | `0xa96dc` | `+0x1e8` |
| exception consume | `0xb0eac` | `0xa96f0` | helper call |
| `DeleteLocalRef` | `0xb0d04` | `0xa9585` | `+0xb8` |

Source-level behavior:

```cpp
if (object == nullptr || byteArray == nullptr) {
    *status = 3;
    return;
}

jclass objectClass = GetObjectClass(object);
if (objectClass == nullptr || consumeException()) {
    *status = 18;
    delete objectClass when non-null;
    return;
}

jmethodID method = GetMethodID(objectClass, "update", "([B)V");
if (method == nullptr || consumeException()) {
    *status = 18;
    DeleteLocalRef(objectClass);
    return;
}

CallVoidMethod(object, method, byteArray);
if (consumeException()) {
    *status = 28;
}
DeleteLocalRef(objectClass);
```

There is no returned object or output publication. A successful call does not
clear a preexisting nonzero status.

## C++ recovery

Implementation and regression symbols:

```text
RecoveredJniByteArrayUpdateOperationsB081c
runRecoveredJniByteArrayUpdateB081c
recoveredJniByteArrayUpdateB081cRegression
```

The direct regression covers null object, null byte array, success, incoming
nonzero status, class-null, class-exception, method-null, method-exception,
call-exception, exact event order, exact `update`/`([B)V` constants, byte-array
forwarding and class-local-reference cleanup.

## Verification

Dedicated verifier:

```bash
python3 .omx/static-audit-20260713/analyze_jni_byte_array_update_b081c.py
```

The verifier checks both FDEs, both caller FDEs and call sites, the four decoded
constants, both once-lock protocols, exact JNI vtable offsets, all three
exception consumers, terminal statuses, C++ regression tokens and recovered
inventory status.

## Original-SO observation-only corroboration

JUnit test:

```text
unidbg-adjust-runner/src/test/java/local/JniByteArrayUpdateNativeIntegrationTest.java
```

The local ARM64 SO was executed once under Unidbg with read-only `CodeHook`
observers at the helper entry, `GetMethodID`, `CallVoidMethod`, exception result,
`DeleteLocalRef` and the caller status reload. No register, branch, JNI object,
return value or target byte was modified.

Observed assertions:

```text
entry count                         1
incoming status                    0
caller status after return         0
method name                        update
method signature                   ([B)V
entry object == CallVoidMethod obj true
entry byte[] == CallVoidMethod arg true
method ID                          nonzero
call exception                     0
DeleteLocalRef count               1
deleted class ref                  nonzero
```

Result:

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
```

Log:

```text
.omx/static-audit-20260713/jni-byte-array-update-b081c-unidbg-retry.log
```
