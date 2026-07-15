# ARM64 `0xbce98` JNI DisplayMetrics getter — hybrid recovery

## 1. File range and call site

```text
ARM64:  0xbce98..0xbd6a8
x86_64: 0xb0994..0xb1071

ARM64 caller:  0x8e9c8 inside producer 0x8746c
x86_64 caller: 0x90b18 inside producer 0x88475
```

Recovered signature:

```cpp
void readDisplayMetrics(
    uint32_t* status,
    JNIEnv* env,
    jobject resources,
    jobject* output);
```

## 2. Static method and JNI evidence

Cross-ABI decoded constants:

```text
ARM64  0x145490 XOR 0x89 -> "getDisplayMetrics\0"
ARM64  0x1454b0 XOR 0xc0 -> "()Landroid/util/DisplayMetrics;\0"

x86_64 0x13df30 XOR 0x74 -> "getDisplayMetrics\0"
x86_64 0x13df50 XOR 0x78 -> "()Landroid/util/DisplayMetrics;\0"
```

JNI vtable calls:

| Offset | JNI operation |
|---:|---|
| `+0x0f8` | `GetObjectClass` |
| `+0x108` | `GetMethodID` |
| `+0x110` | `CallObjectMethod` |
| `+0x0b8` | `DeleteLocalRef` |

Exactly three exception-consumer calls follow the class, method and object
calls. The `CallObjectMethod` result is published before its exception state is
consumed.

## 3. Recovered control flow

```cpp
if (resources == nullptr) {
    *status = 3;
    *output = nullptr;
    return;
}

clazz = GetObjectClass(env, resources);
classException = consumeException(env);
if (clazz == nullptr || classException) {
    *status = 18;
    if (clazz != nullptr) DeleteLocalRef(env, clazz);
    *output = nullptr;
    return;
}

method = GetMethodID(
    env, clazz,
    "getDisplayMetrics",
    "()Landroid/util/DisplayMetrics;");
methodException = consumeException(env);
if (method == nullptr || methodException) {
    *status = 18;
    DeleteLocalRef(env, clazz);
    *output = nullptr;
    return;
}

*output = CallObjectMethod(env, resources, method);
callException = consumeException(env);
if (callException || *output == nullptr) {
    *status = 28;
}
DeleteLocalRef(env, clazz);
if (*status != 0) {
    *output = nullptr;
}
```

Incoming nonzero status does not suppress JNI. An otherwise successful call
preserves that status and clears the output after class cleanup. The returned
DisplayMetrics local reference is transferred to the caller and not deleted by
this helper. Status/output/environment pointers are not validated.

## 4. Producer data flow

The producer obtains a `DisplayMetrics` object through this helper, then passes
that exact object to recovered `0xb21b4` twice:

```text
widthPixels  -> scratch+0x60
heightPixels -> scratch+0x64
```

## 5. Isolated dynamic corroboration

The observation-only Unidbg hook ran offline for V4, V4-repeat and V5. Each run
observed:

```text
caller          libsigner.so+0x8e9cc
incoming status 0
resources       non-null
returned type   android/util/DisplayMetrics
final status    0
```

The returned handle was then the object used by the `widthPixels` and
`heightPixels` reads, which returned `1440` and `3120` for the fixed profile.
Failure semantics remain established by static cross-ABI proof and the C++
regression, not inferred from this success-only trace.

## 6. Evidence files

```text
.omx/static-audit-20260713/disasm-bce98-bd6a8.txt
.omx/static-audit-20260713/disasm-x86-b0994-b1071.txt
.omx/static-audit-20260713/analyze_jni_display_metrics_getter_bce98.py
.omx/static-audit-20260713/unidbg-detector-scratch-bce98-raw.log
native-reimplementation/recovered_primitives.cpp
```
