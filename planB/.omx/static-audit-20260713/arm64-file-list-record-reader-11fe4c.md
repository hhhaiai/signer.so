# ARM64 length-prefixed file-list record reader `0x11fe4c..0x12014c`

## Recovered ABI and node layout

```cpp
struct Node {                   // size 0x18
    uint32_t tag;               // +0x00
    uint32_t payloadLength;     // +0x04
    void* ownedPayload;         // +0x08
    Node* next;                 // +0x10
};

void helper(
    uint32_t* status,
    FileListOwner* owner,
    uint32_t expectedRecordSize,
    FILE* stream);
```

## Exact behavior

1. Append a zeroed 24-byte node through `0x11fccc` **before** reading any
   bytes.  Thus all later failures leave an owned partial node for the existing
   list destructor.
2. If the append stage leaves nonzero status, return without reading.
3. Read a four-byte tag into `node+0x00` as one item.
4. Only on success, read a four-byte payload length into `node+0x04` as one
   item.
5. Compare `uint64(payloadLength) + 8` with the zero-extended caller-supplied
   `uint32 expectedRecordSize`.  A mismatch writes status `8`.
6. Allocate `calloc(1, payloadLength)` and publish the result at `node+0x08`
   before the null test.  A null result writes status `1`.
7. Read the payload as one item whose size is exactly `payloadLength`.
   Header/payload short reads use the recovered checked-fread status `2`.

The addition is 64-bit after zero extension; it is not a wrapping 32-bit
`payloadLength + 8` comparison.

## Evidence addresses

```text
0x11fe78        append node
0x11fefc        node+4 second-header address
0x120090..0a4   first four-byte checked read
0x1200c4..0d8   second four-byte checked read
0x120050        payloadLength load
0x120054..05c   64-bit payloadLength+8 comparison
0x120008..018   mismatch status 8
0x1200f8..0100  calloc(1, payloadLength)
0x120124        payload publication at +0x08
0x120078..088   allocation status 1
0x120020..034   exact-length one-item payload read
```

## Owned C++ and regression

- `runRecoveredFileListRecordRead11fe4c`
- `recoveredFileListRecordRead11fe4cRegression`

Regression coverage includes a complete record, size mismatch, append with a
preexisting status, partial-node ownership, list tail invariants and cleanup.
