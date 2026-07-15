# ARM64 post-detector predicates `0x76f2c` and `0x77f7c`

Both FDEs are one-field, one-marker boolean predicates used by the
`0x12a30` first-match aggregator.

| FDE | Scratch field | Encoded marker | Predicate |
|---|---:|---|---|
| `0x76f2c..0x77f7c` | `+0x20` | `0x1447b4 XOR 0x80 = "haima"` | overlapping ASCII-CI substring |
| `0x77f7c..0x78f68` | `+0x08` | `0x1447bc XOR 0x5b = "vmos"` | overlapping ASCII-CI substring |

Null and empty candidate fields return false.  Exact and case-varied matches,
prefix/suffix containment and embedded matches return true; incomplete markers
return false.  The source equivalents are `runRecoveredHaimaPredicate76f2c`
and `runRecoveredVmosPredicate77f7c`.

Reproduction:

```bash
python3 .omx/static-audit-20260713/analyze_post_detector_predicates_76f2c_77f7c.py
```

The local ARM64 interpreter follows the flattened bodies with initialized
one-time marker state and proves the observable predicate results.  It also
checks raw ELF marker decoding, scratch loads and the C++ regressions.
