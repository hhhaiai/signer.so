# ARM64 expected Java-HMAC producer

## Closed flow

```text
Map/Object at context+0x10
  -> 0x9b684: Object.toString()Ljava/lang/String;
  -> 0x9c030: String.getBytes()[B
  -> 0xc8ec0: select key route using context+0x0c Android API
       API >= 23: 0xc9250, AndroidKeyStore.getKey("key2", null)
       API 18..22: 0xc9988, adjust_keys/encrypted_key legacy unwrap route
       API < 18: unsupported status 18
  -> 0xca648:
       Mac.getInstance("HmacSHA256")
       Mac.init(java.security.Key)
       Mac.update(mapToStringBytes)
       Mac.doFinal() -> byte[]
  -> 0x94bc0: copy expected byte[] into native memory
  -> 0xef00..0xef08: compare supplied and expected bytes
  -> mismatch: correction 0x07 via 0x13548c
```

## API selection evidence

- `0xc8ee0`: reads `context+0x0c` Android API.
- `0xc8f40`: compares API against `0x16` (22); the greater branch is API >=23.
- `0xc912c`: calls `0xc9250`, the AndroidKeyStore route.
- `0xc9178`: calls `0xc9988`, the legacy preference/RSA route.
- `0xc91c4`: compares against `0x11` (17), closing API <18 as unsupported.

## Decoded constants

| VMA | XOR | value |
|---|---:|---|
| `0x144ad8` | `0x6a` | `toString` |
| `0x144af0` | `0x47` | `()Ljava/lang/String;` |
| `0x144b08` | `0xd2` | `getBytes` |
| `0x144954` | `0xb6` | `()[B` |
| `0x145760` | `0xec` | `AndroidKeyStore` |
| `0x145770` | `0x81` | `key2` |
| `0x145798` | `0xdc` | `adjust_keys` |
| `0x1457a8` | `0xcd` | `encrypted_key` |
| `0x1457b8` | `0xb6` | `AES` |
| `0x145748` | `0x9f` | `HmacSHA256` |
| `0x144fe0` | `0x29` | `javax/crypto/Mac` |
| `0x1449a8` | `0x1e` | `getInstance` |
| `0x145000` | `0xc4` | `(Ljava/lang/String;)Ljavax/crypto/Mac;` |
| `0x1449ec` | `0x3b` | `init` |
| `0x145030` | `0xad` | `(Ljava/security/Key;)V` |
| `0x145048` | `0xa5` | `update` |
| `0x145050` | `0x7b` | `([B)V` |
| `0x144a18` | `0xa6` | `doFinal` |

## Compatibility consequence

The C++ cryptographic equivalent is HMAC-SHA256 over the bytes produced by
Android's no-argument `String.getBytes()`, using the key selected by the API
route. A complete platform adapter must preserve Java default-charset behavior,
KeyStore exceptions, legacy unwrap failures, null results and pending JNI
exceptions; accepting arbitrary raw key bytes is only an engine-level adapter,
not the complete Android behavior.
