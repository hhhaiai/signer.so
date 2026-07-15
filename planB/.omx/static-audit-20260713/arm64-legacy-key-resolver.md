# ARM64 API 18..22 legacy wrapped-key resolver

## Closed success path

```text
Context
  -> 0xb479c: getSharedPreferences("adjust_keys", MODE_PRIVATE)
  -> 0xc0d84: getString("encrypted_key", null)
  -> 0x93014: android.util.Base64.decode(value, DEFAULT)
  -> 0xcac40:
       KeyStore.getInstance("AndroidKeyStore") / load(null)
       getEntry("key2", null) -> PrivateKeyEntry
       Cipher.getInstance("RSA/ECB/PKCS1Padding")
       init(DECRYPT_MODE, privateKey)
       doFinal(encryptedBytes) -> raw 16-byte legacy HMAC key
  -> 0xbd6a8: new SecretKeySpec(rawKey, "AES")
  -> 0xca648: Mac.init(Key), update(data), doFinal()
```

The flattened block order in `0xc9988` is not source order; the helper identities,
arguments and recovered Java source close the observable success order above.

## Helper evidence

| Address | Recovered role |
|---|---|
| `0xb479c` | `Context.getSharedPreferences(String,int)` |
| `0xc0d84` | `SharedPreferences.getString(String,String)` |
| `0x93014` | `Base64.decode(String,int)` |
| `0xcac40` | AndroidKeyStore `key2` RSA/PKCS1 private-key unwrap |
| `0xbd6a8` | `SecretKeySpec(byte[],String)` constructor |

## Full orchestrator closure

The companion `analyze_legacy_key_resolver_c9988_full.py` interprets the complete
flattened FDE and proves preexisting-status behavior, null forwarding, Base64
status 26 normalization, RSA boolean gating, final output publication and the
exact four-reference cleanup order. Direct C++ is
`runRecoveredLegacyWrappedKeyResolverC9988(...)`.
