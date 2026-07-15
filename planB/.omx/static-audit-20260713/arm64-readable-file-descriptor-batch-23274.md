# Readable-file descriptor batch at `0x23274..0x23730`

The function consumes the same 0x100-byte record layout as the recovered
system-property batch at `0x24444`:

```text
+0x00 path
+0x08 uint64 descriptors[20]
+0xa8 uint32 kinds[20]
+0xf8 uint64 descriptorCount
```

Recovered behavior:

1. Allocate one 0x801-byte stack buffer and initially clear all bytes.
2. Before each record, clear the first 0x800 bytes while reusing the same
   buffer address. The final byte remains zero by the initial/read-helper
   invariant.
3. Call the recovered `0xd6a2c` helper as `read(path, 0x801, buffer)`.
4. Read failure skips the record and performs no descriptor calls.
5. Read success forwards the buffer, each ordered descriptor at `+0x08`, and
   its parallel kind at `+0xa8` to `0x23730`.
6. The first match increments the caller's existing uint16 counter, with
   modulo-65536 wrap, and skips remaining descriptors in that record.
7. Records are processed in ascending order with a 0x100-byte stride.

Static proof:

```bash
python3 .omx/static-audit-20260713/analyze_readable_file_descriptor_batch_23274.py
```
