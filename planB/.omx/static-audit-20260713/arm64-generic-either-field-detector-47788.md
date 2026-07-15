# ARM64 generic either-field detector `0x47788..0x47f84`

The detector guards the scratch and correction-array pointers, then performs
two ordered checks using the recovered case-sensitive substring predicate
`0x127a78` and the shared once-decoded `generic` marker:

```text
1. scratch+0x10
2. scratch+0x20, only when the first field is null or does not match
```

The first successful check short-circuits to the mutation block. If both fields
are null or miss, the function returns without mutation. Case folding is not
performed here, so `Generic` does not match `generic`.

On a match:

```cpp
index = *correctionCount;
*correctionCount = index + 1;
corrections[index] = 0x16;
*score = *score + (1.0f - *score);
```

Repeatable evidence check:

```bash
python3 .omx/static-audit-20260713/analyze_generic_either_field_detector_47788.py
```
