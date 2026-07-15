# ARM64 `0xa948c` JNI indexed object reader — hybrid recovery

## 1. Range and caller

```text
ARM64:  0xa948c..0xa9d44
x86_64: 0xa4cd9..0xa53a9

ARM64 caller:  0x8e358 inside producer 0x8746c
x86_64 caller: 0x93ca9 inside producer 0x88475
```

The corrected x86_64 endpoint comes directly from its `.eh_frame` FDE. The
caller shape is:

```cpp
void readIndexedObject(
    uint32_t* status,
    JNIEnv* env,
    jobject collection,
    int32_t index,
    jobject* output);
```

## 2. Decoded method contract

Both ABIs once-decode the same method name and signature:

```text
ARM64  0x144fbc XOR 0x47 -> "get\0"
ARM64  0x144fc0 XOR 0x77 -> "(I)Ljava/lang/Object;\0"

x86_64 0x13da5c XOR 0xc5 -> "get\0"
x86_64 0x13da60 XOR 0x76 -> "(I)Ljava/lang/Object;\0"
```

JNI vtable operations:

| Offset | Operation |
|---:|---|
| `+0x0f8` | `GetObjectClass` |
| `+0x108` | `GetMethodID` |
| `+0x110` | `CallObjectMethod` |
| `+0x0b8` | `DeleteLocalRef` |

The exception consumer is called exactly once after each of the first three
JNI operations. `CallObjectMethod` receives the original object, recovered
method ID, and the sign-preserved 32-bit index.

## 3. Recovered behavior

```cpp
if (collection == nullptr) {
    *status = 3;
    *output = nullptr;
    return;
}

clazz = GetObjectClass(env, collection);
classException = consumeException(env);
if (clazz == nullptr || classException) {
    *status = 18;
    if (clazz != nullptr) DeleteLocalRef(env, clazz);
    *output = nullptr;
    return;
}

method = GetMethodID(env, clazz, "get", "(I)Ljava/lang/Object;");
methodException = consumeException(env);
if (method == nullptr || methodException) {
    *status = 18;
    DeleteLocalRef(env, clazz);
    *output = nullptr;
    return;
}

*output = CallObjectMethod(env, collection, method, index);
callException = consumeException(env);
if (callException || *output == nullptr) {
    *status = 28;
}

DeleteLocalRef(env, clazz);
if (*status != 0) {
    *output = nullptr;
}
```

Compatibility details:

- preexisting nonzero status does not skip any JNI operation;
- an otherwise successful call preserves the incoming status and therefore
  clears the returned object pointer;
- a null object result without a JNI exception still overwrites status with
  `28`;
- only the class local reference is deleted; a successful returned object
  reference is transferred to the caller;
- status, output and environment pointers are not validated.

If the helper is entered with a nonzero status and `get(index)` returns a
non-null local reference, the original helper clears the pointer without
deleting that returned local reference. The C++ model preserves this behavior
for compatibility rather than silently repairing ownership.

## 4. Producer data flow

The producer first calls recovered `0xa8978` to obtain `size()I`, then calls
`0xa948c` while iterating the collection. The returned object is subsequently
used by sensor field readers and the owned-pair appender, producing the sensor
name/vendor pair in the detector scratch.

## 5. Isolated dynamic corroboration

The default-off, observation-only Unidbg hook was run with Maven offline. V4,
V4-repeat and V5 all exited successfully and identically observed:

```text
caller          libsigner.so+0x8e35c
incoming status 0
collection      non-null
index           0
returned type   android/hardware/Sensor
final status    0
```

The producer simultaneously reported `size()=1` and emitted:

```text
LSM6DSO | STMicroelectronics
```

This confirms the successful producer role. Error-state and cleanup semantics
remain grounded in cross-ABI static control flow and C++ regression cases, not
in this success-only dynamic observation.

## 6. Artifacts

```text
.omx/static-audit-20260713/disasm-a948c-a9d44.txt
.omx/static-audit-20260713/disasm-x86-a4cd9-a53a9.txt
.omx/static-audit-20260713/analyze_jni_indexed_object_method_reader_a948c.py
.omx/static-audit-20260713/unidbg-detector-scratch-a948c-raw.log
native-reimplementation/recovered_primitives.cpp
```
