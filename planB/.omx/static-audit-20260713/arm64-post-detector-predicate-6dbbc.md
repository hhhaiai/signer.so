# ARM64 post-detector predicate `0x6dbbc..0x6f758`

This boolean predicate is the ninth entry in the `0x12a30` first-match chain.
It loads the pointer at `scratch+0x58` and searches it for one protected marker:

```text
0x144710 XOR 0xb7 = "leapdroid\0"
```

The flattened body implements an overlapping ASCII-only case-insensitive
substring search.  Null and empty fields return false.  Exact, case-varied,
prefix, suffix, and embedded occurrences return true; incomplete or separated
spellings return false.

The direct source equivalent is
`runRecoveredLeapdroidPredicate6dbbc`.  Its field access deliberately uses
`memcpy` at byte offset `0x58` because that three-word portion of the current
scratch layout remains opaque until the adjacent predicates are recovered.

Reproduction:

```bash
python3 .omx/static-audit-20260713/analyze_post_detector_predicate_6dbbc.py
```

The analyzer statically interprets the ARM64 body for the complete behavior
matrix, verifies the raw ELF marker bytes and XOR key, and checks the C++
implementation and regression hooks.
