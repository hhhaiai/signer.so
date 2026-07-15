# ARM64 bounded file-list sequence reader `0x12014c..0x1203e4`

## Recovered ABI

```cpp
void helper(
    uint32_t* status,
    FileListOwner* owner,
    uint32_t totalSize,
    FILE* stream);
```

## Stream format and flow

The function consumes a bounded sequence:

```text
repeat until cumulative offset reaches totalSize:
    uint32 recordSize
    recordBody[recordSize]   // parsed by 0x11fe4c
```

Exact behavior:

1. Initialize a 32-bit cumulative offset to zero.
2. While `offset < totalSize` using the native unsigned comparison, read one
   four-byte `recordSize` through the checked-fread wrapper.
3. Pass that size, the same owner and the same stream to recovered nested
   reader `0x11fe4c`.
4. If either read stage leaves nonzero status, return without advancing the
   cumulative offset.
5. Otherwise compute `offset = previousOffset + recordSize + 4` with 32-bit
   wraparound.
6. When the offset is no longer less than the bound, require exact equality.
   A non-equal value writes status `8`.
7. `totalSize == 0` performs no stream or owner dereference and preserves the
   incoming status.

## Evidence addresses

```text
0x1201ec        zero 32-bit offset
0x120328..334   save offset and test offset < totalSize
0x12035c..370   four-byte recordSize read
0x1202f4..304   call 0x11fe4c with recordSize
0x120308..320   nested status gate
0x12033c..354   uint32 previous + recordSize + 4
0x1202e4..2ec   exact-total termination test
0x1203a0..3a4   overshoot status 8
```

## Owned C++ and regression

- `runRecoveredFileListReadSequence12014c`
- `recoveredFileListReadSequence12014cRegression`

The regression covers two complete records, list/tail ordering, overshoot,
short outer-prefix input, zero-size no-op and full cleanup.
