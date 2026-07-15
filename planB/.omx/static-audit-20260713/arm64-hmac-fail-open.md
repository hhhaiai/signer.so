# ARM64 expected Java-HMAC fail-open propagation

## Result

`0xe6c0` initializes its stage result to false. Only a completed match or a
completed mismatch sets that result to true. A mismatch emits correction
`0x07`; resolver, Java-object, Mac producer or byte-array-copy failure leaves
the stage false and does not emit `0x07`.

`0xcbbd4` observes the boolean and can leave its integrity sub-stage early.
However, the upper signing orchestrator calls `0xcbbd4` at `0xcc254` and does
not inspect `w0`; it immediately continues with the environment dispatcher at
`0xcc25c`, later reaching final consumer `0x11da64` at `0xcc28c`.

Therefore the native behavior is:

```text
expected-HMAC infrastructure failure
  -> skip integrity verdict/correction 0x07
  -> continue native signing pipeline
```

It is not, by itself:

```text
expected-HMAC infrastructure failure -> JNI null signature
```

This is a fail-open integrity stage. The ordinary Java wrapper often prevents
entry into native code when its own key/HMAC operation throws, but a faithful
native reimplementation must still preserve the native call-level behavior.
