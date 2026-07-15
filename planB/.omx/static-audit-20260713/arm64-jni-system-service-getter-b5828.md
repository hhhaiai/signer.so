# ARM64 `0xb5828` JNI Context system-service getter

## Range and caller

```text
ARM64:  0xb5828..0xb70e4
x86_64: 0xac4d5..0xad0a5

ARM64 caller:  0x8af24 inside producer 0x8746c
x86_64 caller: 0x9089f inside producer 0x88475
```

Recovered input shape:

```cpp
void getSystemService(
    uint32_t* status,
    JNIEnv* env,
    jobject context,
    const char* staticServiceFieldName,
    jobject* output);
```

The producer passes `SENSOR_SERVICE` as the field name.

## Static strings

Both ABIs decode the same constants:

```text
android/content/Context
getSystemService
(Ljava/lang/String;)Ljava/lang/Object;
Ljava/lang/String;
```

The static field name is a caller parameter rather than a hardcoded helper
constant, making the helper reusable for other `Context.*_SERVICE` fields.

## Exact JNI order

```text
1. FindClass("android/content/Context")
2. GetMethodID("getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;")
3. GetStaticFieldID(callerFieldName, "Ljava/lang/String;")
4. GetStaticObjectField(...)
5. CallObjectMethod(context, method, serviceNameString)
```

Five exception-consumer calls follow those stages. Two `DeleteLocalRef` sites
release the service-name String before the Context class.

## Status and ownership

```text
null context or field name                 -> status 3
FindClass/GetMethodID/GetStaticFieldID     -> status 18 on null/exception
GetStaticObjectField null/exception        -> status 28
CallObjectMethod null/exception            -> status 28
```

Incoming nonzero status does not suppress JNI. On an otherwise successful
path it is preserved, both temporary refs are released, and the returned
object pointer is cleared. A successful service object local ref is transferred
to the caller.

## Dynamic corroboration

V4, V4-repeat and V5 all observed:

```text
field           SENSOR_SERVICE
field value     "sensor"
returned type   android/hardware/SensorManager
final status    0
```

Verbose JNI tracing also corroborated the static five-stage order. This is
auxiliary evidence only; error paths and cleanup order are represented by the
cross-ABI verifier and C++ regression.

## Evidence

```text
.omx/static-audit-20260713/disasm-b5828-b70e4.txt
.omx/static-audit-20260713/disasm-x86-ac4d5-ad0a5.txt
.omx/static-audit-20260713/analyze_jni_system_service_getter_b5828.py
.omx/static-audit-20260713/unidbg-jni-order-b5828.log
.omx/static-audit-20260713/unidbg-detector-scratch-system-service-raw.log
native-reimplementation/recovered_primitives.cpp
```
