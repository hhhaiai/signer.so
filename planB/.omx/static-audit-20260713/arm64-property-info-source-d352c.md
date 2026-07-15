# Property-info mapped source creator `0xd352c`

Cross-ABI mapping:

```text
ARM64:  0xd352c..0xd3d90
x86_64: 0xc0cdd..0xc1318
```

Both implementations contain the same 23 opaque state constants and decode
the same fixed path:

```text
/dev/__properties__/property_info
```

The helper always runs even with a preexisting nonzero status.  It allocates a
zeroed 0x30-byte source, initializes fd at +0x00 to -1, checks `access(path,4)`,
opens with `openat(AT_FDCWD,path,O_RDONLY,0)`, runs fstat, and requires
`st_size >= 24`.  It stores the size at +0x10, maps the whole file with
`mmap(nullptr,size,PROT_READ,MAP_PRIVATE,fd,0)`, stores the pointer at +0x08,
and copies the first 24 mapped bytes to source+0x18.  These copied header bytes
place the string-table offset at source+0x24 and root-node offset at +0x2c.

Failure statuses are 2 for the source calloc, 8 for access/open, 10 for fstat,
and 12 for a file shorter than 24 bytes.  Each failure calls the d3d90 mapped
source destructor and returns null.  Success preserves incoming status.

There is no mmap-result gate: pointer publication is immediately followed by
16-byte and 8-byte loads from the returned address.  `MAP_FAILED` or null
therefore faults before the state machine can assign a status or invoke normal
rollback.  The first 24 bytes are copied without validating magic, version, or
embedded offsets; later parser stages trust those offsets as documented in the
d28d0 evidence.

C++ implementation and non-executed regression entry:

```text
RecoveredPropertyInfoHeaderD352c
RecoveredPropertyInfoSourceCreateOperationsD352c
runRecoveredPropertyInfoSourceCreateD352c
recoveredPropertyInfoSourceCreateD352cRegression
```
