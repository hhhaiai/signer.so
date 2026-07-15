# Filtered detector record stages `0x13dc8` and `0x14078`

## Cross-ABI mapping

| Stage | ARM64 | x86_64 |
|---|---|---|
| packed-transition | `0x13dc8..0x14078` | `0x1668d..0x168bd` |
| fixed-loopback | `0x14078..0x14338` | `0x168bd..0x16af8` |

Both functions receive a record-pointer array, its count, and the native
context. They initialize a local status and `{filteredCount,filteredPointer}`
pair, then call `0x34f9c` to retain kind-10 records with the three required
non-null fields.

## Packed-transition stage

```text
filter through 0x34f9c
if filter succeeds:
    count through 0x34bf4
    if uint16 count != 0:
        correction 0x04
        context flag bit 0
    realtime comparison with 15000.0ms
if status != 0:
    correction 0x32 through 0x14380
unconditionally OR context+0xe0 with 0x0004000000000010
free(filteredPointer)
return status == 0
```

## Fixed-loopback stage

The parallel stage substitutes:

```text
counter:        0x34954
hit correction: 0x0a
error helper:   0x143b4
final mask:     0x0004000000000400
```

`0x34954` requires candidate `kind28==1`, `required08==0x0100007f`, and a
matching `opaque10` key. Both ABIs load the same `15000.0` double threshold.
Allocation failure skips both the counter and timing call, applies correction
`0x32`, still applies the final mask, frees the null temporary pointer, and
returns false.

Machine-checkable evidence:

```text
.omx/static-audit-20260713/analyze_detector_record_stages_13dc8_14078.py
```
