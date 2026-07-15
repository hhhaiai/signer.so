# JNI class-assignability helper `0x9816c`

## Scope and FDE mapping

Authorized local static recovery of ARM64:

```text
0x9816c..0x9885c
```

Cross-ABI equivalent:

```text
x86_64 0x9a484..0x9a9a6
```

The sole caller edge is ARM64 `0x9255c -> 0x9816c`, mirrored by x86_64
`0x9664f -> 0x9a484`.

## Parameter roles

The ARM64 argument registers are:

```cpp
void helper(
    std::uint32_t* status, // x0
    JNIEnv* env,          // x1
    jobject object,       // x2
    const char* className,// x3
    std::uint8_t* output);// x4
```

`JNIEnv`, object and class name are caller inputs. The helper contains no
hardcoded Java object or runtime class name.

## Recovered JNI flow

```cpp
if (object == null || className == null) {
    status = 3;
    output = false;
    return;
}

objectClass = GetObjectClass(object);
consumeException();
if (objectClass == null || exception) status = 18;

targetClass = FindClass(className);
consumeException();
if (targetClass == null || exception) status = 18;

output = IsAssignableFrom(objectClass, targetClass) != 0;
consumeException();
if (exception) status = 28;

DeleteLocalRef(objectClass);
DeleteLocalRef(targetClass);
if (status != 0) output = false;
```

JNI vtable evidence:

| Operation | ARM64 | x86_64 |
|---|---:|---:|
| `GetObjectClass` `+0xf8` | `0x98454..0x98458` | `0x9a692` |
| first exception consumer | `0x98464 -> 0x92a20` | `0x9a6a7 -> 0x96a44` |
| `FindClass` `+0x30` | `0x98690..0x98694` | `0x9a845` |
| second exception consumer | `0x986a0 -> 0x92a20` | `0x9a84e -> 0x96a44` |
| `IsAssignableFrom` `+0x58` | `0x987ac..0x987b0` | `0x9a924` |
| third exception consumer | `0x987c8 -> 0x92a20` | `0x9a934 -> 0x96a44` |
| first `DeleteLocalRef` `+0xb8` | `0x98548..0x9854c` | `0x9a746` |
| second `DeleteLocalRef` `+0xb8` | `0x985e4..0x985e8` | `0x9a7d5` |

The native return is normalized to one byte. ARM64 executes
`tst w0,#0xff -> cset -> strb` at `0x987b4..0x987c4`; x86_64 executes
`testb -> setne` at `0x9a927..0x9a92e`.

## Status and ownership

| Condition | Status |
|---|---:|
| null object or class name | `3` |
| null/exception from `GetObjectClass` or `FindClass` | `18` |
| exception from `IsAssignableFrom` | `28` |

Non-null local references are deleted in object-class then target-class order.
An incoming nonzero status does not suppress JNI, but the final output byte is
cleared. This matches the surrounding JNI helper convention without inventing
default objects or class names.

## C++ recovery

```text
RecoveredJniClassAssignableOperations9816c
runRecoveredJniClassAssignable9816c
recoveredJniClassAssignable9816cRegression
```

The direct regression covers true/false results, incoming nonzero status, both
null-input gates, null and exception failures for both class acquisitions,
assignability exception, output clearing, and exact two-reference cleanup
order.

Automated verifier:

```bash
python3 \
  .omx/static-audit-20260713/analyze_jni_class_assignable_9816c.py
```
