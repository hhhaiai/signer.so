# Detector record pointer filter at `0x34f9c..0x352d4`

Recovered ABI:

```cpp
bool helper(
    uint32_t* status,
    Record* const* input,
    uint64_t inputCount,
    Record*** output,
    uint64_t* outputCount);
```

`Record` has observable fields at offsets `+0x08`, `+0x18`, `+0x20`, and
`+0x28`. The final field is compared as a 64-bit value.

## Behavior

1. Call `calloc(inputCount, 8)` unconditionally.
2. On allocation failure, overwrite status with `2`, leave both output slots
   untouched, and return false.
3. Walk exactly `inputCount` input pointers in ascending order. Input pointers
   and each record pointer are not null-guarded by the native function.
4. Select a record only when fields `+0x08`, `+0x18`, and `+0x20` are all
   non-null and the 64-bit field at `+0x28` equals `10`.
5. Append selected pointers densely while preserving input order.
6. On success, publish the allocated array and selected count, preserve the
   incoming status, and return true. A zero-match result still owns a non-null
   allocation whenever `calloc` returned one.

Both ARM64 and x86_64 implement the same allocation, field conditions,
selection order, status, output publication, and boolean return.

Static proof:

```bash
python3 .omx/static-audit-20260713/analyze_detector_record_filter_34f9c.py
```
