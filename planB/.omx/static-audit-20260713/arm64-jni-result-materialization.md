# ARM64 JNI result materialization

## Confirmed call chain

```text
0x11da64 final consumer
  -> 0xa334 removes temporary/native metadata and clears context+0x18
  -> protected engine produces native result bytes
  -> 0xaf3c materializes those bytes as a Java byte[] at context+0x18
       0x9548c: NewByteArray(length)
       0x95680: SetByteArrayRegion(array, 0, length, nativeBytes)
  -> 0xcbe98 returns context+0x18
```

## `0xa334` is cleanup, not the byte-array constructor

- `0xaec8`: `str xzr, [x21,#0x18]` clears `context+0x18`.
- `0xaecc/0xaee4/0xaefc/0xaf38`: four calls/tail-call to `0x9aa5c`.
- `0x9aa5c` resolves `Map.remove(Object)` using the decoded strings
  `remove` and `(Ljava/lang/Object;)Ljava/lang/Object;`, creates a Java string
  through JNI vtable offset `0x538`, invokes the object method through offset
  `0x110`, and deletes local references through offset `0xb8`.
- The four decoded keys are `headers_id`, `native_version`,
  `adj_signing_id`, and `algorithm`.

## Java byte-array creation

`0xaf3c(status, env, context, nativeLength, nativeBytes)` computes
`context+0x18` at `0xaf7c` and passes that address to `0x9548c`.

`0x9548c` calls `NewByteArray(length)` at JNI vtable offset `0x580` and stores
the returned reference through the supplied output pointer. A pending exception
or a null return writes status `31` and clears the output. A preexisting nonzero
status is preserved but also clears the newly-created output reference.

## Java byte-array copy

At `0xbd18..0xbd34`, `0xaf3c` loads the reference from `context+0x18` and calls
`0x95680(status, env, array, 0, nativeLength, nativeBytes)`.

- null target array -> status `3`, no JNI call;
- non-null target -> `SetByteArrayRegion` at JNI vtable offset `0x680`;
- pending exception after the copy -> status `32`;
- successful copy -> status unchanged.

## Final native/JNI return semantics

- `0x11ea38..0x11ea48`: final consumer returns true exactly when status is zero.
- `0xcc1c8..0xcc1d8`: the orchestrator loads `context+0x18` into its return slot.
- `0xcc450`: the JNI-facing return value is that slot.

Thus a successful result is a non-null Java `byte[]` containing the exact
native envelope bytes. Array creation failure clears the reference. A copy
exception leaves the allocated reference in `context+0x18`, but status `32`
and the pending Java exception mean there is no normal Java return. The
standalone null-target status `3` is not reached through the normal `0xaf3c`
chain because `0x9548c` converts a null allocation to status `31` first.
`0xcc47c` is not a second result materializer.
