# ARM64 getline-compatible helper `0xd6ed8..0xd7890`

Cross-ABI mapping:

```text
ARM64:  0xd6ed8..0xd7890
x86_64: 0xc36c3..0xc3e4a
```

Both FDEs contain the same 28 opaque state constants and the same five libc
operations: `fgets`, `__strlen_chk`, `calloc`, `realloc`, and `memcpy`.  Direct
call sites are ARM64 `0xd9e1c/0xe69ec` and x86_64 `0xc8abb/0xdde9b`.

Recovered behavior:

1. Inputs are `char **line`, `size_t *capacity`, and `FILE *stream`; pointer
   arguments are not guarded.
2. A null `*line` forces `*capacity=128`, performs `calloc(128,1)`, publishes
   the result, and returns `-1` on allocation failure.
3. A non-null buffer with nonzero capacity is cleared across exactly
   `[line,line+capacity)`.  The flattened byte/halfword/aligned loop is proven
   equivalent to that full clear for every pointer alignment modulo four.
4. Reads use `fgets(chunk,128,stream)`.  A final newline is removed; an empty
   line therefore returns zero and stores an empty string.
5. Chunks without newline are appended.  Initial EOF returns `-1`; EOF after
   accumulated chunks returns their total length.
6. Required capacity is `total+1`.  Growth uses
   `(required & ~127) + 128`, so an exact 128-byte multiple receives one extra
   128-byte block.
7. Capacity is published before `realloc`, and the returned pointer directly
   overwrites `*line`.  Failure therefore retains the new capacity, loses the
   caller-visible old pointer, leaks the old allocation, and returns `-1`.
8. The copied line is always NUL terminated.  The native newline probe reads
   `chunk[strlen(chunk)-1]`; conforming successful `fgets(...,128,...)` is
   nonempty, but the helper itself has no explicit zero-length guard.

C++ implementation and non-executed regression entry:

```text
RecoveredGetLineOperationsD6ed8
runRecoveredGetLineD6ed8
recoveredGetLineD6ed8Regression
```
