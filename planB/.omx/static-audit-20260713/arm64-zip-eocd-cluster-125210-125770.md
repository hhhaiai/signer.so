# ZIP EOCD matcher and backward scanner

## Function mapping

| Semantics | ARM64 | x86_64 |
|---|---|---|
| EOCD signature matcher | `0x125210..0x125770` | `0x11d040..0x11d3b2` |
| backward offset scanner | `0x125770..0x1259b8` | `0x11d3b2..0x11d585` |

## Marker recovery

The matcher has a four-byte process-global marker protected by a one-time
atomic guard. The stored encodings differ by ABI:

```text
ARM64  data 0x145f88: 0b 10 5e 5d, XOR 0x5b
x86_64 data 0x13ea28: 78 63 2d 2e, XOR 0x28
decoded:              50 4b 05 06
```

`50 4b 05 06` is the ZIP End of Central Directory signature. The source-level
representation uses the immutable decoded bytes. `0x125210` zeroes a local
four-byte buffer, calls the checked fread wrapper for one item of size four,
and only after a complete read compares all four bytes in order.

## Backward scan

ZIP EOCD has a 22-byte fixed minimum size and a maximum 65535-byte comment.
The native scanner therefore uses:

```text
offset = -22
while uint32(offset) > 0xfffeffeb:
    if checked_fseek(stream, offset, SEEK_END) == false:
        break
    if matches_50_4b_05_06(stream):
        break
    offset--
return offset
```

The visited range is `-22..-65556`, exactly 65535 candidate offsets. Full
exhaustion returns `-65557`. A seek failure or match returns the current
offset. The scanner does not inspect or clear the shared status value.

Machine-checkable evidence:

```text
.omx/static-audit-20260713/analyze_zip_eocd_cluster_125210_125770.py
```
