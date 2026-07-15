# ARM64 `0xaf3c` native result-builder transaction

This report reads only the existing ARM64 objdump. It does not load or execute
`libsigner.so`.

## Confirmed success order

The flattened state transitions recover this runtime order; call-site address
order is not runtime order:

```text
NewByteArray                         0xafb4
SetByteArrayRegion                  0xbd34
Map.put(headers_id, 9)              0xc544
Map.put(adj_signing_id, 1400000)    0xc7f4
Map.put(native_version, 3.67.0)     0xbffc
Map.put(algorithm, adj8)            0xc6a4
return                              0xcdb8
```

The key/value addresses at the four calls are direct evidence:

| call | key/value VMAs | decoded pair |
|---:|---|---|
| `0xc544` | `0x142ea8`, `0x142eb4` | `headers_id=9` |
| `0xc7f4` | `0x142ed0`, `0x142ea0` | `adj_signing_id=1400000` |
| `0xbffc` | `0x142eb8`, `0x142ec8` | `native_version=3.67.0` |
| `0xc6a4` | `0x142ee0`, `0x142eec` | `algorithm=adj8` |

## Failure and rollback behavior

- `NewByteArray` failure state `0x73a9e0897a6e742c` and
  `SetByteArrayRegion` failure state `0x2773b06d406c84a3` converge to
  `0x43c03deaa70c8d82`, dispatched at `0xc250`.
- `headers_id` and `adj_signing_id` put failures also converge directly to
  the same rollback state.
- `native_version` failure is selected through `x27`; `0xb1c4..0xb1cc`
  constructs the same common rollback state before the conditional dispatcher
  jump at `0xb1d0`. It does not branch to `0xbaac`.
- Any nonzero status after a metadata put reaches `0xc250`, which
  calls `0xa334`. That cleanup clears `context+0x18` and removes all four
  metadata keys. A cleanup failure may overwrite the transaction status.
- Final success selects state `0x4c81a55be310eef5` and returns at `0xcdb8`
  without calling rollback.

## Lazy decode calls are synchronization, not fallible metadata producers

The calls to `0x139800` are byte compare-and-swap operations used to guard
one-time XOR decoding of static key/value buffers. They return the previous
guard byte and choose decode-versus-wait paths; they do not allocate and do
not introduce an additional transaction status code.
