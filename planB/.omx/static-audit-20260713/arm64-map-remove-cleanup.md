# ARM64 `Map.remove` status and cleanup model

## Function and arguments

`0x9aa5c..0x9b680` implements the equivalent of:

```text
removeFromMap(status, env, map, keyCString)
```

Entry validation requires non-null `env`, `map`, and `keyCString`.

## Failure status mapping

| stage | ARM64 evidence | native status |
|---|---:|---:|
| invalid env/map/key | `0x9aed4` | `3` |
| `GetObjectClass` exception/null | `0x9ae78 -> 0x9aea0` | `18` |
| `GetMethodID(remove, signature)` exception/null | `0x9ae78 -> 0x9aea0` | `18` |
| `NewStringUTF(key)` exception/null | `0x9aef8..0x9af10` | `34` |
| `CallObjectMethod(Map.remove)` pending exception | `0x9b060..0x9b07c` | `28` |

A successful call leaves the incoming status word unchanged. Later failures
overwrite an earlier nonzero status because the helper does not short-circuit
on the incoming status value.

## JNI references

- class reference: deleted when non-null;
- key `jstring`: deleted when it was created, including the unusual case where
  `NewStringUTF` returned non-null while an exception was reported;
- `Map.remove` return object: stored in `x19` at `0x9afcc`, but never passed to
  `DeleteLocalRef` and never otherwise consumed;
- opaque anchor: `x23` is initialized from the flattened initial-state constant,
  saved at `0x9b394`, and passed to `DeleteLocalRef` at `0x9af28..0x9af38` on
  paths that created a key string. The corresponding x86_64 function stores
  `%r13` and performs the same vtable `+0xb8` call. This is not the
  `CallObjectMethod` result.

The opaque-anchor deletion is documented as an observed target behavior, not
executed by the platform-neutral C++ model. A real JNI adapter should expose it
as a compatibility observation until isolated ART testing establishes whether
release ART ignores, warns on, or rejects the invalid local-reference value.

## `0xa334` caller behavior

`0xa334` clears `context+0x18`, then unconditionally invokes `0x9aa5c` four
times for:

```text
headers_id
adj_signing_id
native_version
algorithm
```

There is no status check between the calls. A later remove failure can overwrite
an earlier failure code; a later successful remove leaves an earlier failure
unchanged.
