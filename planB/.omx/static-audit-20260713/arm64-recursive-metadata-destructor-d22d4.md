# Recursive metadata-node destructors `0xd22d4` and `0xd4220`

Cross-ABI mapping:

```text
ARM64 content: 0xd22d4..0xd28d0
x86_64:       0xbfe08..0xc0340
ARM64 owner:  0xd4220..0xd4244
x86_64:       0xc1713..0xc1725
```

`0xd22d4` is a content destructor for a 0x30-byte recursive node:

```text
+0x00 char* firstOwnedString
+0x08 char* secondOwnedString
+0x10 uint32 firstChildCount
+0x14 reserved
+0x18 Node* firstChildren
+0x20 uint32 secondChildCount
+0x24 reserved
+0x28 Node* secondChildren
```

The two ABIs contain the same 21 opaque state constants.  Destruction order is
strictly: first children in ascending order, first array free/pointer/count
clear, second children in ascending order, second array free/pointer/count
clear, first string free/clear, second string free/clear.  Recursive children
are contiguous 0x30-byte elements and are not individually freed; their parent
array allocation is freed once after every child content is destroyed.

`0xd4220` preserves the outer pointer, calls the content destructor, and then
tail-calls `free` on that same pointer.  A null pointer still reaches
`free(nullptr)`.  Neither helper validates counts, child-array bounds, cycles,
or recursion depth; reserved fields +0x14/+0x24 are unchanged.

C++ implementation and non-executed regression entry:

```text
RecoveredRecursiveMetadataNodeD22d4
runRecoveredRecursiveMetadataNodeContentDestroyD22d4
runRecoveredRecursiveMetadataNodeDestroyD4220
recoveredRecursiveMetadataNodeDestroyD22d4D4220Regression
```
