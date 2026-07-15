# Java retry/reset/lockdown static proof

Source of truth: `classes.jar` bytecode rendered in `original-java-javap.txt`.

```text
if processLockdown: return
if null/empty arguments: return
insert activity_kind/client_sdk
attempts = 2
while attempts > 0:
  ensure key; compute Java HMAC
  UnsupportedApi:
    lockdown = true; remove temporary keys; rethrow
  InvalidKeyException or UnrecoverableKeyException:
    attempts--
    delete AndroidKeyStore key2
    remove adjust_keys/encrypted_key and apply
  other Exception:
    remove temporary keys; rethrow
if attempts == 0:
  lockdown = true; remove temporary keys; return
nativeResult = nSign(...)
if nativeResult == null:
  remove temporary keys; return
signature = Base64.encodeToString(nativeResult, NO_WRAP /* flag 2 */)
remove temporary keys
```

The exception table covers bytecode offsets `147..167` only. Reset bytecode
starts at `302`, so an exception raised while deleting `key2` or clearing the
preference escapes directly and does not reach the ordinary temporary-key
cleanup blocks. The C++ control-flow model intentionally preserves this edge.
