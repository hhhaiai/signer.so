# ARM64 API >=23 AndroidKeyStore resolver

## Recovered call-level behavior

```text
keyStore = KeyStore.getInstance("AndroidKeyStore")
if JNI helper failed: return false

keyStore.load(null)
if JNI helper failed: DeleteLocalRef(keyStore); return false

key = keyStore.getKey("key2", null)
if JNI helper failed: DeleteLocalRef(keyStore); return false

*output = key        // copied without a null-key rejection
success = true
DeleteLocalRef(keyStore)
return success
```

## Important null distinction

At `0xc9818..0xc9838`, the object stored by the `getKey` helper is copied to the
caller output and the local success flag is set to one. There is no `cbz`, null
comparison or null-to-failure conversion on that key object. Therefore:

```text
getKey JNI call succeeded + returned null => resolver returns true with null key
getKey JNI helper/pending-exception failure => resolver returns false
```

The caller must preserve this distinction. A null key reaches the later
`Mac.init(Key)` path, where Java/JNI behavior determines the eventual failure.

## Local-reference ownership

The temporary KeyStore object is guarded and released through the JNI vtable
entry at offset `0xb8` (`DeleteLocalRef`) on success and post-creation failures.
The returned Key reference is transferred to the caller and is not deleted by
`0xc9250`.

## Helper addresses

| Address | Role |
|---|---|
| `0xa4450` | `KeyStore.getInstance(String)` |
| `0xa5308` | `KeyStore.load(LoadStoreParameter)` |
| `0xa6c9c` | `KeyStore.getKey(String,char[])` |
| `0xc9250` | API >=23 resolver and ownership/error orchestration |
