# Fixed unordered uint32-pair predicate `0x87158..0x8746c`

Cross-ABI mapping:

```text
ARM64  0x87158..0x8746c
x86_64 0x881ea..0x88475
```

The leaf reads two `uint32_t` values from scratch offsets `+0x60` and `+0x64`.
It compares them against eight fixed pairs, accepting either orientation:

```text
(0x0320,0x029a)
(0x035c,0x02dc)
(0x035c,0x0300)
(0x035c,0x02a0)
(0x035c,0x02d0)
(0x037c,0x02dc)
(0x02a0,0x017a)
(0x0398,0x029e)
```

The four 16-byte vector loads differ in address between ABIs but produce the
same 64-byte table in the same order. A pair matches when either
`field60==first && field64==second` or the fields are swapped. The native
function has no null scratch guard. It returns true on the first match and
false when the index reaches eight.

Machine-checkable evidence:

```text
.omx/static-audit-20260713/analyze_unordered_fixed_pair_matcher_87158.py
```
