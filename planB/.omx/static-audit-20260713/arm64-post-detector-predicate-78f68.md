# ARM64 post-detector predicate `0x78f68..0x7ba5c`

This is the thirteenth and final boolean predicate in the `0x12a30`
first-match chain.  It combines two fixed scratch fields:

```text
scratch+0x20 contains any one of:
  0x1447c4 XOR 0x38 = "HWEVA"
  0x1447d0 XOR 0xfc = "eva-al00"
  0x1447e0 XOR 0x46 = "zerofltezc"

scratch+0x30 must also contain:
  0x1447f0 XOR 0x66 = ":6.0.1/RB3N5C"
```

All four searches are overlapping ASCII-only case-insensitive substring
matches.  Both field conditions are required.  Null fields, markers placed in
the wrong field, incomplete markers, or only one matching side return false.

The direct source equivalent is
`runRecoveredDeviceBuildPairPredicate78f68`.

Reproduction:

```bash
python3 .omx/static-audit-20260713/analyze_post_detector_predicate_78f68.py
```

The analyzer interprets the complete ARM64 FDE over null, exact, case-varied,
prefix/suffix, incomplete and swapped-field matrices.  It also validates all
four raw ELF XOR markers, both fixed-field loads, the final return bit, and the
C++ implementation/regression hooks.
