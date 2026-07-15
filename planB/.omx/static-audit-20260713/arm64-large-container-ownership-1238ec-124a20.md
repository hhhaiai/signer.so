# ARM64 `0x68` large-container ownership cluster

## Node layout

```cpp
struct LargeContainerNode {
    ThreeListTwoFieldAggregate aggregate; // +0x00, size 0x38
    uint32_t firstOuterValue;              // +0x38
    uint32_t secondOuterValue;             // +0x3c
    FileListOwner fourth;                  // +0x40
    OwnedFileBuffer buffer;                // +0x50
    LargeContainerNode* next;              // +0x60
}; // size 0x68
```

The two fields at `+0x38/+0x3c` explain the eight-byte gap between the recovered
`0x38` aggregate and the fourth list owner.

## `0x1238ec..0x123a54`: append

- allocate `calloc(1, 0x68)`;
- null allocation writes status `1` and leaves the outer owner unchanged;
- initialize embedded owner tail slots at `+0x08`, `+0x18`, `+0x30` and
  `+0x48`;
- publish through the outer tail slot;
- advance the outer tail slot to `node+0x60`.

## `0x123a54..0x123a80`: content-only destructor

Exact order:

1. aggregate at `+0x00` through `0x123254`;
2. fourth list at `+0x40` through `0x121260`;
3. owned buffer at `+0x50` through the tail call to `0x1221b8`.

The outer node is not freed here.

## `0x124608..0x124774` and `0x124a20`

The list destructor follows `next` at `+0x60`, destroys contents before freeing
the node and restores `{head=null, tailSlot=&head}`.  `0x124a20` is a four-byte
tail alias to this destructor.

Owned C++ and regression:

- `runRecoveredLargeContainerAppend1238ec`;
- `runRecoveredLargeContainerContentsDestroy123a54`;
- `runRecoveredLargeContainerListDestroy124608`;
- `runRecoveredLargeContainerListDestroy124a20`;
- `recoveredLargeContainerOwnershipCluster1238ec124a20Regression`.
