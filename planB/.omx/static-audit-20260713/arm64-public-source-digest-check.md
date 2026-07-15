# ARM64 public-source digest validation (`0xd9cc..0xe674`)

Target: `libsigner.so` SHA-256 `8be033d3423258ac6975c17813eae0ee41c9c743f90ab40e40fa9c1c58eef371`.

## `0xd9cc..0xddc4`: candidate SHA-1 comparator

The caller passes `context+0xf0` as the expected 20-byte digest and
`candidate+0x10` as a `{uint32 length; uint32 padding; uint8_t* data;}`
descriptor.  `0xda1c` loads the descriptor data pointer and the null path
returns false.  The non-null path calls `0x11f238`, `0x11f264`, and `0x11f414`,
which are respectively the SHA-1 initialize/update/final sequence.  The update
arguments at `0xdc48..0xdc54` are descriptor `+0x08` and `+0x00`.  The final
20-byte result is compared byte-for-byte with the first argument; the return is
the equality bit (`0xdd9c`).

The x86_64 counterpart is `0x11c20` and has the same descriptor layout and
20-byte comparison.

## `0xddc4..0xe674`: parser and candidate routing

Entry initializes status to zero and calls `0x124c90(&status,
context->ownedPointer110)`.  Any nonzero status emits correction `0x38`.
Otherwise `0x127194(&status, parser)` populates the parser; its nonzero status
also emits correction `0x38`.

On parser success the candidate pointers are read in this exact order:

```text
parser+0x38
parser+0x28
parser+0x18
```

Each non-null candidate is passed as `candidate+0x10` to `0xd9cc`.  The first
matching SHA-1 terminates the search successfully.  Null candidates are
skipped.  If at least one candidate was present but every present candidate
mismatched, `0xe254..0xe2f0` writes correction `0x2a` and sets context flag bit
zero.  If all three candidates are null, correction `0x2a` is not written.

All paths then OR `0x0100040000000000` into `context+0xe0` at
`0xe61c..0xe634` and call parser destructor `0x125074` at `0xe638`.

The x86_64 counterpart is `0x11f34..0x12519`; its visible semantic blocks are:

```text
0x11f8f  parser constructor
0x12412  parser population
0x121fa  candidate +0x38 comparison
0x1247c  candidate +0x28 comparison
0x12334  candidate +0x18 comparison
0x12262  correction 0x2a
0x1238b  correction 0x38
0x124e4  final mask
0x124f0  parser destructor
```

This is an APK/public-source certificate-digest validation stage.  It does not
read request crypto parameters and is not a final-envelope algorithm selector.
