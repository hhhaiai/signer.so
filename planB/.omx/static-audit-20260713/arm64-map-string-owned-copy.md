# ARM64 Map string owned-copy helper

## Range and ABI

- ARM64 FDE: `0xaebf8..0xaf438`
- nSign call-site: `0xcce40`

| register | recovered meaning |
|---|---|
| `x0` | `uint32_t* status` |
| `x1` | `JNIEnv*` |
| `x2` | Java `Map` reference |
| `x3` | decoded C-string key |
| `x4` | `char**`/owned native output |

## Recovered behavior

1. Null Map or key clears output and writes status `2`.
2. Call `0xadbf4`, the recovered JNI `Map.get` helper.
3. A null value with status zero is a successful null output.
4. For a non-null Java String, `0x92b24` acquires modified UTF-8 bytes and
   byte length.
5. Allocate `length + 1`; allocation failure writes status `3`.
6. Copy exactly `length` bytes and append NUL.
7. Release UTF chars through JNIEnv vtable `+0x550` and delete the Map.get
   local reference through vtable `+0xb8`.
8. Any nonzero final status leaves the owned output null.

## Owned C++

- `modelRecoveredMapStringCopy()`
- `runRecoveredMapStringCopy()`
