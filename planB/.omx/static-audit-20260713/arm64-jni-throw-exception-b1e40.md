# JNI `java/lang/Exception` ThrowNew helper `0xb1e40..0xb21b4`

## Scope

The ARM64 FDE at `0xb1e40..0xb21b4` is a JNI exception-construction helper.
It is not statically reachable from the two exported JNI entry points in the
current direct-call graph, but it is part of the authoritative 388-FDE target
and therefore remains in the all-function recovery scope.

Cross-ABI equivalent:

```text
ARM64:  0xb1e40..0xb21b4  size 0x374
x86_64: 0xaa064..0xaa362  size 0x2fe
```

## Recovered signature

Source-level contract:

```cpp
void helper(
    uint32_t* status,
    JNIEnv* env,
    const char* message);
```

The function has no caller-visible return value.  It does not validate any of
the three pointers and does not gate execution on an incoming nonzero status.

## XOR-once class name

The ARM64 process-global 20-byte ciphertext is at VMA `0x1450f0`, file offset
`0x13d0f0`:

```text
3a3126317f3c313e377f152833352024393f3e50
```

XOR key `0x50` produces:

```text
java/lang/Exception\0
```

The other three packaged ABIs use different ciphertexts and keys but produce
the same plaintext:

```text
x86_64 file offset 0x135b90, key 0xf6
ARMv7  file offset 0x112370, key 0x52
x86    file offset 0x130100, key 0x95
```

ARM64 and x86_64 disassembly both show adjacent lock/initialized bytes and an
acquire byte compare-exchange plus release unlock.  ARM64 calls the recovered
compiler CAS helper at `0x139800`.

The C++ model preserves:

```text
atomic byte lock
initialized byte
encoded 20-byte ARM64 storage
XOR exactly once
release unlock
```

## JNI sequence

The direct JNI behavior is:

```text
class = FindClass(env, "java/lang/Exception")     vtable +0x30
classException = consumeException(env)             ARM64 0x92a20

if class == null or classException:
    *status = 18
else:
    ThrowNew(env, class, callerMessage)             vtable +0x70
    ignore ThrowNew return

if class != null:
    DeleteLocalRef(env, class)                      vtable +0xb8
```

Important boundaries:

- only the exception produced by `FindClass` is consumed/described/cleared;
- a successful `ThrowNew` normally creates a pending Java exception, and this
  helper intentionally does not consume it;
- `ThrowNew` is still executed when incoming `*status` is already nonzero;
- success preserves the incoming status;
- `FindClass` null or exception overwrites the status with `18`;
- a non-null class is deleted even when the `FindClass` exception consumer
  reports an exception;
- a null class is not passed to `DeleteLocalRef`.

## C++ symbols

```text
kRecoveredJniThrowExceptionClassEncodedB1e40
RecoveredJniThrowExceptionClassStateB1e40
acquireRecoveredJniThrowExceptionClassB1e40
RecoveredJniThrowExceptionOperationsB1e40
runRecoveredJniThrowExceptionB1e40WithState
runRecoveredJniThrowExceptionB1e40
recoveredJniThrowExceptionB1e40Regression
```

The regression covers:

1. first-call decode and success path;
2. second call without a second XOR;
3. null caller message forwarding;
4. ignored nonzero `ThrowNew` return;
5. null class -> status `18`, no throw and no delete;
6. non-null class plus consumed exception -> status `18`, no throw, delete;
7. incoming nonzero status preservation on success;
8. exact operation order.

## Verification

```bash
python3 .omx/static-audit-20260713/analyze_jni_throw_exception_b1e40.py
clang++ -std=c++17 -Wall -Wextra -Werror \
  -fsyntax-only native-reimplementation/recovered_primitives.cpp
./native-reimplementation/build-and-test.sh
```

Coverage effect:

```text
all ARM64 FDEs: 321 recovered / 0 partial / 67 unknown
JNI-reachable:  277 recovered / 0 partial / 44 unknown
```

The JNI-reachable count does not change because the function currently has no
direct or cross-FDE-tail caller from either exported JNI entry point.
