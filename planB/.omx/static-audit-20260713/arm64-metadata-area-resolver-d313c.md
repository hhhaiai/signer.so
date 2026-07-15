# Dot-separated metadata area-name resolver `0xd313c`

Cross-ABI mapping:

```text
ARM64:  0xd313c..0xd352c
x86_64: 0xc0912..0xc0cdd
```

The two implementations contain the same 14 opaque state constants and each
calls `strchr`, `strncmp`, and `strcmp` exactly once in the flattened body.
Arguments are a 0x30-byte recursive metadata root and a property name.  The
returned pointer is an owned-string pointer stored in the tree; the resolver
does not allocate or transfer ownership.

For every non-final dot-separated segment, the helper scans node+0x18 using
the uint32 count at +0x10.  Children are contiguous 0x30-byte nodes.  It calls
`strncmp(child.firstOwnedString, segment, separator-segment)` and descends into
the first matching child, then continues at `separator+1`.  There is no
terminator/equal-length check on the child string, so a shorter query segment
can match the prefix of a longer child name.  An empty segment passes length
zero to `strncmp` and therefore selects the first child when the array is
nonempty.

When no dot remains, the helper scans node+0x28 using the count at +0x20 and
requires full `strcmp(child.firstOwnedString, finalSegment)==0`.  It returns
that leaf's second owned string or null when no match exists.  Native code does
not validate the root, property name, counts, child pointers, or child strings.

C++ implementation and non-executed regression entry:

```text
runRecoveredMetadataAreaNameResolverD313c
recoveredMetadataAreaNameResolverD313cRegression
```
