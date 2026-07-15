# ARM64 JNI acquisition helpers `0x92b24` and `0x92ddc`

## `0x92b24..0x92ddc`: modified UTF-8 acquisition

Recovered ABI:

```cpp
void helper(
    uint32_t* status,
    JNIEnv* env,
    jstring value,
    const char** output_chars,
    uint64_t* output_utf_length);
```

Evidence and order:

1. `0x92b50/0x92b78` forwards the length output to recovered helper
   `0x927c4` (`GetStringUTFLength`).
2. Only a zero status advances to `0x92d44..0x92d58`, which calls JNIEnv
   vtable `+0x548`, `GetStringUTFChars(value, nullptr)`.
3. `0x92d60` publishes the returned pointer before consuming a pending JNI
   exception through `0x92a20` at `0x92d68`.
4. A pending exception or a null returned pointer reaches the status-`28`
   store at `0x92d34..0x92d3c` (`mov w10, #0x1c` is at `0x92d38`).
5. Every nonzero final status reaches `0x92d10..0x92d2c`, which clears both
   the UTF pointer and UTF length outputs.

## `0x92ddc..0x93014`: array length acquisition

Recovered ABI:

```cpp
void helper(
    uint32_t* status,
    JNIEnv* env,
    jarray value,
    uint32_t* output_length);
```

Evidence and order:

1. `0x92e58` tests the array reference. A null reference selects status `3`
   at `0x92fb0..0x92fb8` and clears the output at `0x92fc8..0x92fcc`.
2. A non-null reference calls JNIEnv vtable `+0x558`, `GetArrayLength`, at
   `0x92f40..0x92f50`, even if the incoming status is already nonzero.
3. `0x92f58` writes the raw 32-bit `jsize` result before calling exception
   consumer `0x92a20` at `0x92f60`.
4. A pending exception selects status `28` at `0x92fdc..0x92fe4`.
5. Every nonzero final status clears the 32-bit output at `0x92fc8..0x92fcc`.

## Owned C++ and regression coverage

- `runRecoveredJniStringUtfChars92b24`
- `recoveredJniStringUtfChars92b24Regression`
- `runRecoveredJniArrayLength92ddc`
- `recoveredJniArrayLength92ddcRegression`

The regressions cover null input, preexisting nonzero status, success, JNI
exception, null UTF result, raw signed `jint/jsize` preservation, JNI call
counts, the null `isCopy` pointer, and final output clearing.
