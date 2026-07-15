# ARM64 Java Mac HmacSHA256 producer

## Call-level flow

```text
mac = Mac.getInstance("HmacSHA256")
if helper failed: return false

mac.init(key)        // key may be null; no native null-to-failure conversion
if helper failed: DeleteLocalRef(mac); return false

mac.update(data)
if helper failed: DeleteLocalRef(mac); return false

result = mac.doFinal()
if helper failed: DeleteLocalRef(mac); return false

copy result byte[] to native storage through 0x94bc0
success = copy-helper status == 0
DeleteLocalRef(result) when non-null
DeleteLocalRef(mac) when non-null
return success
```

The producer uses JNI helper status as the failure signal. Java null objects are
not silently rewritten into another key or an empty digest. A null Mac receiver,
null Key, or null doFinal result reaches the next JNI/helper operation, whose
status/pending exception controls failure.

## Helpers

| Address | Role |
|---|---|
| `0xa9d44` | `Mac.getInstance(String)` |
| `0xab130` | `Mac.init(Key)` |
| `0xab870` | `Mac.update(byte[])` |
| `0xac1d8` | `Mac.doFinal()` |
| `0x94bc0` | Java byte[] length/allocation/region copy to native storage |
| `0xca648` | orchestration, status propagation and local-ref cleanup |
