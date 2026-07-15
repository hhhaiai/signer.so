# ARM64 `0xb21b4` JNI int-field reader — static recovery

## Function and cross-ABI mapping

```text
ARM64:  0xb21b4..0xb2978
x86_64: 0xaa362..0xaa8bb
```

Both ranges are exact `.eh_frame` FDEs.  The only ARM64 calls are at
`0x8c320` and `0x8d564` inside detector-scratch producer `0x8746c`; the
x86_64 counterparts are `0x8e91c` and `0x9374d` inside `0x88475`.

The five arguments are:

```cpp
void readJniIntField(
    uint32_t* status,
    JNIEnv* env,
    jobject object,
    const char* fieldName,
    uint32_t* output);
```

## Caller data

The ARM64 caller uses two XOR-decoded field-name slots:

```text
0x144850 XOR 0x65 -> "widthPixels\0"
0x144860 XOR 0x31 -> "heightPixels\0"
```

At the call sites:

```text
0x8c2f4  x3 = 0x144860  (heightPixels)
0x8c320  bl 0xb21b4

0x8d538  x3 = 0x144850  (widthPixels)
0x8d564  bl 0xb21b4
```

The once-decoded x86_64 bytes at `0x13dba4` use XOR `0xf1` and decode to
`"I\0"`, the JNI descriptor for an instance `int` field.

## JNI operations

| vtable offset | operation |
|---:|---|
| `+0x0f8` | `GetObjectClass` |
| `+0x0b8` | `DeleteLocalRef` |
| `+0x2f0` | `GetFieldID` |
| `+0x320` | `GetIntField` |

Recovered exception consumer `0x92a20` is called exactly three times: after
`GetObjectClass`, `GetFieldID`, and `GetIntField`.

## Recovered behavior

```cpp
if (object == nullptr || fieldName == nullptr) {
    *status = 3;
    *output = 0;
    return;
}

clazz = GetObjectClass(env, object);
classException = consumeException(env);
if (clazz == nullptr || classException) {
    *status = 18;
    if (clazz != nullptr) DeleteLocalRef(env, clazz);
    *output = 0;
    return;
}

field = GetFieldID(env, clazz, fieldName, "I");
fieldException = consumeException(env);
if (field == nullptr || fieldException) {
    *status = 18;
    DeleteLocalRef(env, clazz);
    *output = 0;
    return;
}

*output = GetIntField(env, object, field);
if (consumeException(env)) {
    *status = 28;
}
DeleteLocalRef(env, clazz);
if (*status != 0) {
    *output = 0;
}
```

Compatibility details:

- a preexisting nonzero status does not skip any JNI acquisition;
- a completely successful call preserves a preexisting status and therefore
  clears the final output;
- null object/name overwrites status with `3`;
- class or field acquisition failure overwrites status with `18`;
- an exception after `GetIntField` overwrites status with `28`;
- the `GetIntField` result is written before exception consumption;
- every non-null class local reference is deleted, including the
  `GetObjectClass`-exception path;
- status, output and `JNIEnv` pointers have no native null validation.

## C++ and verifier

```text
native-reimplementation/recovered_primitives.cpp
  runRecoveredJniIntFieldReaderB21b4
  recoveredJniIntFieldReaderB21b4Regression

.omx/static-audit-20260713/analyze_jni_int_field_reader_b21b4.py
```

The regression covers null object/name, normal height/width reads, preexisting
status, null/exception class results, null/exception field IDs, final int-field
exception, exact `"I"` signature, JNI call order and class-ref cleanup.

## Isolated dynamic corroboration

An opt-in Unidbg `CodeHook` was run through the existing structured-profile
integration test in Maven offline mode. The profile explicitly refuses
`127.0.0.1:27042` and supplies display dimensions `1440 x 3120`; the hook only
observes registers/memory and does not alter execution.

Across V4 repeat and V5 calls, all three runs produced the same evidence:

```text
0x8d564 -> name=widthPixels  output=scratch+0x60  value=1440 (0x5a0)
0x8c320 -> name=heightPixels output=scratch+0x64  value=3120 (0x0c30)
producer return status=0, scratch+0x60/+0x64=0x5a0/0x0c30
```

This dynamically corroborates the static field-name decode, call contract,
successful status path, execution order, and the concrete scratch roles:

```text
scratch+0x60 = display width
scratch+0x64 = display height
```

Full normalized trace evidence:

```text
.omx/static-audit-20260713/unidbg-detector-scratch-trace-20260715.md
```
