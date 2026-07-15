# ARM64 BigInteger unsigned-byte cluster: `0x93fd0` and `0x917a8`

## Scope

Authorized local static recovery of:

```text
adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so
```

Cross-ABI control-flow evidence uses the matching local x86_64 library. No
network access or external host was used.

## FDE and cross-ABI mapping

| Role | ARM64 FDE | x86_64 FDE |
|---|---:|---:|
| `BigInteger.toByteArray()` JNI helper | `0x93fd0..0x94bc0` | `0x97673..0x97d1e` |
| signed Java bytes to caller-owned unsigned big-endian bytes | `0x917a8..0x91d2c` | `0x95bf1..0x9604f` |

The sole recovered caller edge of the unsigned-byte helper is:

```text
ARM64  0x924f0: bl    0x917a8
x86_64 0x965fa: callq 0x95bf1
```

## `0x93fd0`: `BigInteger.toByteArray()` JNI helper

### XOR-once method constants

| ABI | encoded VMA | key | decoded bytes |
|---|---:|---:|---|
| ARM64 | `0x144948` | `0xe2` | `toByteArray\0` |
| ARM64 | `0x144954` | `0xb6` | `()[B\0` |
| x86_64 | `0x13d3e8` | `0xc6` | `toByteArray\0` |
| x86_64 | `0x13d3f4` | `0x1c` | `()[B\0` |

These strings are original protocol constants. The `JNIEnv`, BigInteger
object and output handle remain explicit C++ caller inputs.

### JNI evidence

| Operation | ARM64 | x86_64 |
|---|---:|---:|
| `GetObjectClass` vtable `+0xf8` | `0x943d0..0x943d4` | `0x97938` |
| first exception consumer | `0x943f0 -> 0x92a20` | `0x9794e -> 0x96a44` |
| `GetMethodID` vtable `+0x108` | `0x94834..0x94838` | `0x97b31` |
| second exception consumer | `0x94854 -> 0x92a20` | `0x97b47 -> 0x96a44` |
| `CallObjectMethod` vtable `+0x110` | `0x945cc..0x945d0` | `0x97a43` |
| third exception consumer | `0x945f0 -> 0x92a20` | `0x97a5e -> 0x96a44` |
| `DeleteLocalRef` vtable `+0xb8` | `0x944f0..0x944f4` | `0x979ca` |

Status evidence:

```text
null BigInteger                 -> 3   (ARM64 0x94b84; x86_64 0x97d01)
class or method acquisition     -> 18  (ARM64 0x94a3c/0x94b4c;
                                         x86_64 0x97cd4)
call exception or null byte[]   -> 28  (ARM64 0x943b8; x86_64 0x97921)
```

The returned byte-array local reference is written to the caller output at
ARM64 `0x945d4..0x945d8` / x86_64 `0x97a49..0x97a4e`. A nonzero final status
clears it at ARM64 `0x94ad0` / x86_64 `0x97c87..0x97c8c`. The temporary class
local reference is deleted, while a successful returned byte-array reference
is transferred to the caller.

Recovered source:

```cpp
runRecoveredJniToByteArray93fd0
recoveredJniToByteArray93fd0Regression
```

## `0x917a8`: unsigned big-endian native byte materializer

### Direct helper calls

| Stage | ARM64 | x86_64 |
|---|---:|---:|
| `BigInteger.toByteArray()` | `0x91824 -> 0x93fd0` | `0x95c67 -> 0x97673` |
| `GetByteArrayElements` plus length | `0x91c48 -> 0x95110` | `0x95f82 -> 0x9811d` |
| `ReleaseByteArrayElements` | `0x91b6c -> 0x95834` | `0x95ed2 -> 0x98686` |

### Recovered data transformation

The Java result is a signed two's-complement, big-endian byte array. The native
helper converts it to caller-owned unsigned magnitude bytes as follows:

```cpp
byteArray = BigInteger.toByteArray();
elements, length = GetByteArrayElements(byteArray);

if (length == 0) {
    status = 28;
} else {
    skip = elements[0] == 0 ? 1 : 0;
    nativeLength = sign_extend_int32(length - skip);
    outputLength = nativeLength;
    outputData = calloc(nativeLength, 1);
    if (outputData == nullptr) {
        status = 2;
    } else {
        memcpy(outputData, elements + skip, nativeLength);
    }
}
```

Instruction evidence:

```text
ARM64:
  0x91b48                 length==0 status 28
  0x91bb0..0x91bc0       first-byte zero test and length-skip
  0x91bc4                 sxtw nativeLength
  0x91bd8                 calloc(nativeLength, 1)
  0x91aa0..0x91aa4       memcpy(elements+skip, nativeLength)
  0x91ca4                 allocation-failure status 2

x86_64:
  0x95eb5                 length==0 status 28
  0x95ef5..0x95f03       first-byte zero test and length-skip
  0x95f05                 movslq nativeLength
  0x95f18                 calloc(nativeLength, 1)
  0x95e26..0x95e3d       memcpy(elements+skip, nativeLength)
  0x95fcf                 allocation-failure status 2
```

Only one leading byte is removed, and only when it equals zero. A nonzero
leading byte is preserved. ARM64 `sxtw` and x86_64 `movslq` prove that the
32-bit subtraction result is sign-extended before allocation and publication.

### Ownership and failure publication

Cleanup is:

1. release byte-array elements when the element pointer is non-null;
2. delete the byte-array local reference when both the byte-array handle and
   `JNIEnv` are non-null;
3. if final status is nonzero, clear both caller outputs.

The two output clears are visible at ARM64 `0x91a6c..0x91a88` and x86_64
`0x95e0c..0x95e1a`. The successful `calloc` allocation is transferred to the
caller and is intentionally not freed by this FDE.

Recovered source:

```cpp
runRecoveredBigIntegerUnsignedBytes917a8
recoveredBigIntegerUnsignedBytes917a8Regression
```

The regression covers a nonzero leading byte, one stripped zero sign byte,
zero length, allocation failure, failure of the `toByteArray` stage, failure
of the element-acquisition stage, output clearing and release-before-delete
event order.

## Automated proof

Run:

```bash
python3 \
  .omx/static-audit-20260713/analyze_big_integer_unsigned_bytes_917a8.py
```

The verifier checks both FDE pairs, all four encoded constants, JNI vtable
offsets, three exception consumers, status values, output ownership, direct
helper and caller edges, leading-zero removal, signed widening, allocation,
copy, cleanup, stack-canary exits, C++ regression guards and final coverage
classification.
