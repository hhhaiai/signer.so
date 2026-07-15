# ARM64 mapped-file owner destructor `0xd3d90..0xd3ff0`

Recovered owner fields:

```text
+0x00  int32_t  file descriptor
+0x08  void*    mapping
+0x10  uint64_t mapping length
```

Recovered order:

1. Null owner returns without touching resources (`0xd3df4`).
2. Load mapping from `+0x08`.
3. The native unsigned `(mapping + 1) < 2` test treats exactly `nullptr` and
   `MAP_FAILED` (`-1`) as non-mappings.
4. Every other mapping is passed to `munmap(mapping, owner->mappingLength)`.
5. Load the signed 32-bit descriptor from `+0x00`; only values `>= 0` call
   `syscall(57, fd)`, the AArch64 Linux close syscall.
6. Free the owner last. Return values from munmap and close are ignored.

Owned C++:

- `RecoveredMappedFileOwnerD3d90`
- `runRecoveredMappedFileDestroyD3d90`
- `recoveredMappedFileDestroyD3d90Regression`

Regression coverage includes null owner, null mapping, `MAP_FAILED`, valid
mapping, negative/nonnegative fd, mixed resource combinations, cleanup order
and ignored failure returns.
