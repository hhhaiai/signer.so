# ARM64 `context+0x108` owned-string producer

## Scope

```text
0x16b7c..0x1709c  producer
0x95020..0x95110  ReleaseStringUTFChars guard wrapper
```

C++:

```text
runRecoveredOwnedPointer108Producer()
runRecoveredReleaseStringUtfChars()
```

Repeatable checker:

```text
.omx/static-audit-20260713/analyze_owned_pointer108_producer.py
```

## ABI

```text
x0 = uint32_t* status
x1 = JNIEnv-like pointer
x2 = Java Context-like object
x3 = uint64_t* output108
```

## Recovered flow

Locals are initialized before the first helper:

```cpp
uint64_t javaString = 0;
uint64_t utfChars = 0;
uint64_t utfLength = 0;
```

The source-level flow is:

```cpp
sub_b3230(status, env, javaContext, &javaString);

if (*status == 0) {
    sub_92b24(status, env, javaString, &utfChars, &utfLength);
    if (*status == 0) {
        uint64_t allocationSize = utfLength + 1; // wrapping uint64 add
        uint8_t* copy = (uint8_t*)malloc((size_t)allocationSize);
        if (copy == nullptr) {
            *output108 = 0;
            *status = 2;
        } else {
            copy[utfLength] = 0;                 // before byte-copy loop
            for (uint64_t i = 0; i < utfLength; ++i) {
                copy[i] = ((uint8_t*)utfChars)[i];
            }
            *output108 = (uint64_t)copy;
        }

        releaseStringUtfChars(env, javaString, utfChars);
    }
}

if (javaString != 0 && env != 0) {
    DeleteLocalRef(env, javaString);
}

if (*status != 0) {
    *output108 = 0;
}
```

## Allocation and partial mutation

- The function does not clear caller output at entry.
- First-helper or UTF-acquisition failure reaches common cleanup, then clears
  output because status is nonzero.
- `malloc` uses the wrapping 64-bit value `utfLength + 1`.
- On allocation failure it writes output zero before status `2`; common exit
  clears output again.
- On allocation success, the terminator is written before the copy loop.
- The allocated buffer is not freed in this function; ownership transfers to
  the caller through `output108`.
- Any fault during the native copy occurs before ownership transfer and before
  UTF/local-reference cleanup, matching the native instruction order.

## JNI ownership

`0x95020` checks only the Java string and UTF pointer:

```cpp
if (utfChars != nullptr && javaString != nullptr) {
    env->ReleaseStringUTFChars(javaString, utfChars); // vtable +0x550
}
```

It does not guard a null JNIEnv if the other two arguments are non-null.

The producer calls this wrapper after every allocation attempt reached from a
successful UTF-acquisition helper, including `malloc` failure.  It skips the
release wrapper when the UTF-acquisition helper itself leaves nonzero status.

The Java string local reference is deleted through JNI vtable `+0xb8` only
when both the reference and JNIEnv are non-null.  ReleaseStringUTFChars occurs
before DeleteLocalRef.

## Cross-ABI confirmation

x86_64 `0x18473..0x18909` confirms the same helper order, output clearing,
status `2`, allocation/copy/terminator order, release helper and conditional
DeleteLocalRef.  The ABI-equivalent direct calls are:

| ARM64 | x86_64 |
|---:|---:|
| `0xb3230` | `0xaae64` |
| `0x92b24` | `0x96ae0` |
| `malloc@plt` | `0x132850` |
| `0x95020` | `0x98081` |

The exact Java method implemented inside `0xb3230` and the UTF helper internals
inside `0x92b24` remain separate recovery units; the producer's own behavior
is fully represented without inventing those callee semantics.
