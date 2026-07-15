# Recursive metadata-node parser `0xd28d0`

Cross-ABI mapping:

```text
ARM64:  0xd28d0..0xd313c
x86_64: 0xc0340..0xc0912
```

The two implementations contain the same 24 opaque state constants.  The
four arguments are `uint32_t* status`, the shared source whose data pointer is
at `+0x08`, `const uint8_t** cursor`, and a zero-initialized 0x30-byte metadata
node.  The 0x1c-byte wire descriptor is:

```text
+0x00 uint32 owned-string-pair relative offset
+0x04 uint32 recursive child count
+0x08 uint32 recursive-child offset-table relative offset
+0x0c uint32 reserved, not loaded
+0x10 uint32 reserved, not loaded
+0x14 uint32 string-pair-only child count
+0x18 uint32 string-pair-child offset-table relative offset
```

The parser first publishes `descriptor+0x1c`, redirects the shared cursor to
`source->data + field00`, and calls 0xd2018 for the node's two owned strings.
With zero status it conditionally allocates `calloc(field04, 0x30)`, publishes
the result at node+0x18, resolves each uint32 child offset through the table at
field08 and recursively calls 0xd28d0.  Node+0x10 is incremented only after a
child succeeds.

After the recursive array completes, the parser conditionally allocates
`calloc(field14, 0x30)`, publishes it at node+0x28, resolves offsets through the
table at field18, and calls only 0xd2018 for each element.  These second-array
elements are therefore zeroed leaf nodes containing the owned string pair;
node+0x20 is incremented only after pair materialization succeeds.

Any nonzero status after a materializer/recursive call enters the common
0xd22d4 rollback.  Either calloc failure stores null in the corresponding
published pointer, writes status 2, and uses the same rollback.  A preexisting
nonzero status still permits the initial 0xd2018 stage and then rolls back.
The current child is cleaned by its nested parser or 0xd2018 before the parent
rolls back only the previously published counts.

No native bounds checks exist for the 0x1c-byte descriptor, source-relative
offsets, offset tables, string descriptors, counts, total allocation size, or
recursion depth.  `calloc(uint32_count, 0x30)` delegates multiplication-overflow
handling to libc.  The two reserved wire words and node reserved words are not
used by this parser.

C++ implementation and non-executed regression entry:

```text
RecoveredRecursiveMetadataDescriptorD28d0
RecoveredRecursiveMetadataParserOperationsD28d0
runRecoveredRecursiveMetadataParserD28d0
recoveredRecursiveMetadataParserD28d0Regression
```
