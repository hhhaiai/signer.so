# ARM64 file-list aliases and sized payload reader

## `0x1203e4..0x120550`: list destructor alias

This FDE is behaviorally identical to recovered `0x11fb60`:

- owner head at `+0x00`;
- node next at `+0x10`;
- owned payload at `+0x08`;
- advance owner head before cleanup;
- free payload before node;
- reset owner to `{head=null, tailSlot=&head}`.

Owned C++: `runRecoveredFileListDestroy1203e4`.

## `0x120550..0x1206d0`: node append alias

This FDE is behaviorally identical to recovered `0x11fccc`:

- `calloc(1, 0x18)`;
- null allocation writes status `1` and leaves the owner unchanged;
- publish through the current tail slot;
- advance `tailSlot` to `node+0x10`.

Owned C++: `runRecoveredFileListAppend120550`.

## `0x1206d0..0x120858`: fixed-size payload reader

Recovered ABI:

```cpp
void helper(
    uint32_t* status,
    FileListOwner* owner,
    uint32_t payloadLength,
    FILE* stream);
```

Exact order:

1. Append a node through `0x120550` before publishing any fields.
2. A nonzero post-append status returns with the zeroed partial node owned by
   the list.
3. Store the caller length at node `+0x00`.
4. Allocate `calloc(1, payloadLength)` and publish at node `+0x08` before the
   null test.
5. Null allocation writes status `1`.
6. Otherwise read one item whose size is exactly `payloadLength`; short input
   inherits checked-fread status `2`.

Owned C++: `runRecoveredFileListSizedPayloadRead1206d0`.

Regression:

- `recoveredFileListAliasAndSizedPayload1203e41205501206d0Regression`
- verifies complete payload bytes, node field offsets, preexisting-status
  partial ownership, tail-slot invariants and alias destructor cleanup.
