# ARM64 `0xa8978` JNI `size()` reader — static recovery

## Range and caller

```text
ARM64:  0xa8978..0xa948c
x86_64: 0xa469c..0xa4cd9

ARM64 caller:  0x8da60 inside 0x8746c producer
x86_64 caller: 0x91bc8 inside 0x88475 producer
```

The caller passes status, `JNIEnv*`, an object, and a `uint32_t` output slot:

```cpp
void readSize(
    uint32_t* status,
    JNIEnv* env,
    jobject object,
    uint32_t* output);
```

## Decoded method contract

The process-global slots decode identically across ABIs:

```text
ARM64  0x144fb0 XOR 0xe8 -> "size\0"
ARM64  0x144fb8 XOR 0xc9 -> "()I\0"
x86_64 0x13da50 XOR 0x16 -> "size\0"
x86_64 0x13da58 XOR 0x39 -> "()I\0"
```

JNI vtable operations:

| Offset | Operation |
|---:|---|
| `+0x0f8` | `GetObjectClass` |
| `+0x108` | `GetMethodID` |
| `+0x188` | `CallIntMethod` |
| `+0x0b8` | `DeleteLocalRef` |

The exception consumer is called after each of the first three JNI stages.

## Recovered behavior

```cpp
if (object == nullptr) {
    *status = 3;
    *output = 0;
    return;
}

clazz = GetObjectClass(env, object);
if (clazz == nullptr || consumeException(env)) {
    *status = 18;
    if (clazz != nullptr) DeleteLocalRef(env, clazz);
    *output = 0;
    return;
}

method = GetMethodID(env, clazz, "size", "()I");
if (method == nullptr || consumeException(env)) {
    *status = 18;
    DeleteLocalRef(env, clazz);
    *output = 0;
    return;
}

*output = CallIntMethod(env, object, method);
if (consumeException(env)) {
    *status = 28;
}
DeleteLocalRef(env, clazz);
if (*status != 0) {
    *output = 0;
}
```

Preexisting nonzero status does not suppress JNI calls. A successful JNI path
preserves that status and therefore clears the final output. Status/output/env
pointers are not validated by the native helper.

## Artifacts

```text
.omx/static-audit-20260713/disasm-a8978-a948c.txt
.omx/static-audit-20260713/disasm-x86-a469c-a4cd9.txt
.omx/static-audit-20260713/analyze_jni_size_method_reader_a8978.py
native-reimplementation/recovered_primitives.cpp
```

## Isolated dynamic corroboration

The observation-only Unidbg detector-scratch hook captured this helper during
V4, V4-repeat and V5 runs. All three calls had incoming status zero and returned:

```text
caller:  libsigner.so+0x8da64
status:  0
result:  1
```

The same producer return had `stringCount=1` and one sensor pair
`LSM6DSO | STMicroelectronics`, corroborating that this `size()I` read is the
collection count feeding the producer's sensor iteration. Exact failure states
remain proven by static cross-ABI control flow and the C++ regression rather
than inferred from this success-only runtime sample.

Full normalized runtime evidence:

```text
.omx/static-audit-20260713/unidbg-detector-scratch-trace-20260715.md
```
