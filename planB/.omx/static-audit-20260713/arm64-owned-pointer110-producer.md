# ARM64 `context+0x110` public-source string producer

## Scope

```text
0x179f8..0x18540
```

C++:

```text
RecoveredPublicSourceDirState
acquireRecoveredPublicSourceDir()
runRecoveredOwnedPointer110Producer()
```

Repeatable checker:

```text
.omx/static-audit-20260713/analyze_owned_pointer110_producer.py
```

## ABI

```text
x0 = uint32_t* status
x1 = JNIEnv-like pointer
x2 = Java Context-like object
x3 = context+0x108 owned C string
x4 = uint64_t* output110
```

## Java/JNI flow

The function initializes four Java local refs plus UTF pointer/length to null:

```cpp
uint64_t object1 = 0;
uint64_t object2 = 0;
uint64_t javaString = 0;
uint64_t utfChars = 0;
uint64_t utfLength = 0;
```

It then performs:

```cpp
packageName = env->NewStringUTF((char*)input108);       // vtable +0x538
exceptionState = sub_92a20(env);

if (((exceptionState | (packageName == 0)) & 1) != 0) {
    *status = 34;
} else {
    sub_b3bf4(status, env, javaContext, &object1);
    if (*status == 0) {
        sub_b9cc8(status, env, object1, packageName, 0, &object2);
    }
    if (*status == 0) {
        fieldName = acquireDecodedPublicSourceDir();
        sub_b2978(status, env, object2, fieldName, &javaString);
    }
    if (*status == 0) {
        sub_92b24(status, env, javaString, &utfChars, &utfLength);
    }
}
```

Only bit zero of `sub_92a20`'s return participates in the initial failure test.
The null result bit is ORed into that return before `tst #1`.

## One-time `publicSourceDir` decoder

The writable 16-byte object at ARM64 VMA `0x1430f0` initially contains:

```text
bc b9 ae a0 a5 af 9f a3 b9 be af a9 88 a5 be cc
```

XOR `0xcc` produces:

```text
publicSourceDir\0
```

The surrounding global state uses:

```text
0x146444  byte CAS lock
0x146445  initialized flag
```

Native ordering:

```cpp
while (compare_exchange_acquire(lock, 0, 1) != 0) {}
if (initialized == 0) {
    bytes[0..15] ^= 0xcc;
    initialized = 1;
}
store_release(lock, 0);
```

The lock is released before `sub_b2978` uses the decoded field name.  The C++
state preserves the spin, acquire CAS, decode-once flag and release store.

## UTF copy and statuses

After successful UTF acquisition:

```cpp
if (utfLength == 0) {
    *status = 15;
} else {
    uint64_t allocationSize = utfLength + 1; // wrapping add
    uint8_t* copy = (uint8_t*)malloc((size_t)allocationSize);
    if (copy == nullptr) {
        *output110 = 0;
        *status = 2;
    } else {
        copy[utfLength] = 0;                 // written before copy loop
        for (uint64_t i = 0; i < utfLength; ++i) {
            copy[i] = ((uint8_t*)utfChars)[i];
        }
        *output110 = (uint64_t)copy;
    }
}
```

Status meanings at this wrapper boundary:

| value | trigger |
|---:|---|
| `34` | `NewStringUTF` null or `sub_92a20` low bit set |
| `15` | successfully acquired Java UTF string has zero byte length |
| `2` | native `malloc(length+1)` returned null |

Other nonzero helper statuses propagate unchanged.

## Cleanup and partial mutation

If UTF acquisition completed with status zero, ReleaseStringUTFChars is called
even when the later empty-length or malloc checks fail.  It precedes every
local-reference deletion.

Local refs are conditionally deleted, without an additional JNIEnv null guard,
in exact reverse acquisition order:

```text
javaString
object2
object1
packageName created by NewStringUTF
```

Finally:

```cpp
if (*status != 0) *output110 = 0;
```

The output is not cleared at entry.  A pre-existing output value therefore
survives only if the whole function exits with status zero; native code does
not free a pre-existing value before overwriting or clearing the slot.

## Cross-ABI confirmation

x86_64 FDE `0x18fe3..0x19bdf` confirms:

- NewStringUTF vtable `+0x538`;
- helpers corresponding to ARM64 `0x92a20`, `0xb3bf4`, `0xb9cc8`, `0xb2978`,
  `0x92b24`, and `0x95020`;
- four DeleteLocalRef calls through vtable `+0xb8`;
- statuses `34`, `15`, and `2`;
- wrapping allocation/copy behavior;
- the same cleanup order.

This API/package-source resolution route is an environment/input producer.  It
does not choose the final AES/HMAC envelope algorithm.
