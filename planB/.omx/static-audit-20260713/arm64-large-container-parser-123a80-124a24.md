# ARM64 large-container parser layer `0x123a80..0x124a24`

## `0x123a80..0x124608`: validated `0x68` node

The function appends a node through `0x1238ec` before reading input.

Wire order:

```text
uint32 aggregateSize
aggregate[aggregateSize] -> 0x123288, node+0x00

uint32 firstOuterValue   -> node+0x38
uint32 secondOuterValue  -> node+0x3c

uint32 fourthSize
fourth[fourthSize]       -> 0x12183c, node+0x40

uint32 bufferSize
buffer[bufferSize]       -> 0x122090, node+0x50
```

After the two outer values are read, native code compares `node+0x3c` with
aggregate `+0x24`, then `node+0x38` with aggregate `+0x20`.  Either mismatch
writes status `9` and retains the partial node.  The full fixed overhead is 20
bytes.  Size progression is uint32, overshoot writes status `8` before the
corresponding nested stage, and successful parsing requires exact total size.

## `0x124774..0x124a18`: bounded sequence

This is a zero-total no-op sequence of:

```text
uint32 recordSize
record[recordSize] -> 0x123a80
```

The nested parser runs before uint32 offset advancement.  Reaching or passing
the bound requires exact equality; overshoot writes status `8`.

## `0x124a24..0x124c90`: single-section wrapper

One uint32 length wraps `0x124774`.  `sectionSize+4` is checked for unsigned
overshoot before the nested call and exact equality after it.

Flattened call order, arguments, status `9`, status `8`, sequence loops and
wrapper boundaries are verified by
`analyze_large_container_parser_123a80_124a24.py`.  Owned C++ regression:
`recoveredLargeContainerParserCluster123a80124a24Regression`.
