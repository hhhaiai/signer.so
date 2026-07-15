# ARM64 post-detector predicate `0x59658..0x5a8e0`

This is the second boolean predicate in the `0x12a30` first-match chain.  It
reads the active dynamic-pair count from `scratch+0x870` and indexes sixteen-
byte slots beginning at `scratch+0x70`:

```text
slot+0x00  primary string pointer
slot+0x08  secondary string pointer
```

The protected writable marker is:

```text
0x143368 XOR 0x1d = "microvirt\0"
```

For each active slot, the function performs an overlapping ASCII-only
case-insensitive substring search on both strings.  A slot succeeds only when
both pointers are non-null and both strings contain `microvirt`.  Null or
nonmatching slots are skipped; the first matching pair returns true.  An empty
list, incomplete marker, or matches split between two different slots return
false.

The direct C++ equivalent is
`runRecoveredMicrovirtPairPredicate59658`.

Reproduction:

```bash
python3 .omx/static-audit-20260713/analyze_post_detector_predicate_59658.py
```

The analyzer interprets the complete ARM64 FDE over null, empty, exact,
case-varied, prefix/suffix, multi-slot and split-slot matrices.  It also checks
the raw ELF XOR marker, the `lsl #4` slot stride, both field loads, the native
return bit, and the C++ implementation/regression hooks.
