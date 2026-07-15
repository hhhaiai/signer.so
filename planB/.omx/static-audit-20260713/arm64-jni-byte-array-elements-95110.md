# JNI byte-array acquisition at `0x95110..0x9548c`

Recovered ABI:

```cpp
void helper(
    uint32_t* status,
    JNIEnv* env,
    jbyteArray array,
    void** elements,
    uint32_t* length);
```

## Behavior

1. A null array produces status `3`; no JNI call is made.
2. A non-null array always enters the already recovered `0x92ddc`
   `GetArrayLength` helper, including when status was already nonzero.
3. Only zero status proceeds to `GetByteArrayElements(array, nullptr)` through
   JNI vtable offset `0x5c0`.
4. A pending exception or null returned elements pointer produces status `28`.
5. Any nonzero final status clears both the native elements pointer and the
   32-bit length. Success preserves both outputs.
6. `JNIEnv*`, the two output pointers, and the status pointer are caller-contract
   values and are not null-guarded by the original function.

ARM64 and x86_64 contain the same state transitions, vtable offset, null
`isCopy` argument, and paired cleanup. The callback-driven C++ regression covers
null array, preexisting status, length-stage exception, successful acquisition,
elements-stage exception, and a null elements result.

Static proof:

```bash
python3 .omx/static-audit-20260713/analyze_jni_byte_array_elements_95110.py
```
