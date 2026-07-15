# ARM64 `Map.put` status and cleanup model

`0x9954c..0x9aa58` implements JNI `Map.put(String,String)` with method name
`put` and signature `(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;`.

## Status mapping

| stage | status |
|---|---:|
| null env/map/key/value | `3` |
| `GetObjectClass` exception/null | `18` |
| `GetMethodID` exception/null | `18` |
| key `NewStringUTF` exception/null | `34` |
| value `NewStringUTF` exception/null | `34` |
| `CallObjectMethod(Map.put)` pending exception | `28` |
| success | incoming status unchanged |

## Reference cleanup

The helper conditionally deletes every reference that it actually creates:

- class returned by `GetObjectClass`;
- key `jstring`;
- value `jstring`;
- previous Map value returned by `Map.put`, when non-null.

Unlike `0x9aa5c Map.remove`, this helper's four `DeleteLocalRef` argument slots
are populated by the corresponding live JNI references; no opaque-anchor
deletion was found in this function.
