# ARM64 signer-code trampoline detector `0x13063c..0x1309cc`

The flattened FDE walks a null-terminated outer array of function-entry
tables. Each inner table is null-terminated and has a parallel upper address
bound. Entries at or beyond the bound are skipped. For every entry below its
bound, the native function zeroes an eight-byte local, copies
`min(upperBound - entry, 8)` bytes, and checks:

```text
(firstEightBytes & 0xfffffc1fff000000) == 0xd61f000058000000
```

In little-endian byte order this requires byte 3 to be `0x58` (ARM64 LDR
literal class) and the fixed opcode bits of bytes 4..7 to be an indirect
`BR Xn`; the register fields and LDR literal/register fields are ignored.
The first match returns true. Exhausting every table, null tables, entries at
the bound, truncated seven-byte entries, and `BLR` instead of `BR` return
false.

The static interpreter executes the original ARM64 instructions for empty,
miss, truncated, at-bound, and later-table-hit matrices and verifies the
native `__memcpy_chk(..., 8)` lengths.
