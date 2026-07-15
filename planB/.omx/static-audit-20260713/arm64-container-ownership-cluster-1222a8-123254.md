# ARM64 container ownership cluster `0x1222a8..0x123254`

## `0x1222a8..0x122410`: four-list container-node append

Recovered ABI:

```cpp
ContainerNode* helper(
    uint32_t* status,
    ContainerOwner* outerOwner);
```

The native function allocates exactly `calloc(1, 0x58)`.  A null result writes
status `1` and does not mutate the outer owner.  The allocated node is:

```cpp
struct ContainerNode {
    FileListOwner first;   // +0x00
    FileListOwner second;  // +0x10
    FileListOwner third;   // +0x20
    FileListOwner fourth;  // +0x30
    OwnedFileBuffer buffer;// +0x40
    ContainerNode* next;   // +0x50
}; // 0x58
```

The four embedded `tailSlot` fields are initialized to `node+0x00`, `+0x10`,
`+0x20` and `+0x30`.  Empty and nonempty outer-list publication both advance
the outer `tailSlot` to `node+0x50`.

Owned C++: `runRecoveredContainerAppend1222a8`.

## `0x122410..0x12243c`: node-content destructor

This function does not free the outer `0x58` node.  Its exact order is:

1. destroy the first three list owners with `0x121aac`;
2. destroy the fourth owner at `+0x30` with `0x121260`;
3. tail-call the owned-buffer destructor at `+0x40` through `0x1221b8`.

Owned C++: `runRecoveredContainerNodeContentsDestroy122410`.

## `0x122bb8..0x122d24` and alias `0x122fe4`

The outer destructor walks `next` at node `+0x50`, calls the content destructor
before freeing each node, and finally restores `{head=null, tailSlot=&head}`.
`0x122fe4` is a four-byte unconditional tail branch to this destructor.

Owned C++:

- `runRecoveredContainerListDestroy122bb8`;
- `runRecoveredContainerListDestroy122fe4`.

## `0x123254..0x123288`: two-field aggregate destructor

Recovered layout:

```cpp
struct Aggregate {
    FileListOwner first;   // +0x00
    FileListOwner second;  // +0x10
    uint32_t firstValue;   // +0x20
    uint32_t secondValue;  // +0x24
    FileListOwner third;   // +0x28
}; // 0x38
```

The native order is third list, second list, clear both uint32 fields with one
64-bit store at `+0x20`, then tail-destroy the first list.

Owned C++: `runRecoveredThreeListTwoFieldAggregateDestroy123254`.

## Verification

`recoveredContainerOwnershipCluster1222a8123254Regression` checks:

- exact node and field offsets;
- empty and nonempty tail-slot publication;
- allocation-failure status and no-mutation behavior;
- content-before-node cleanup;
- owned payload/buffer cleanup;
- outer owner reset;
- exact clearing of both fixed uint32 fields.
