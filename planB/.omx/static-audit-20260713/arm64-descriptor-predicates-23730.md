# ARM64 descriptor predicate dispatcher `0x23730`

Target SHA-256:

```text
8be033d3423258ac6975c17813eae0ee41c9c743f90ab40e40fa9c1c58eef371
```

Static constant propagation over the flattened dispatcher gives the following
route table:

| kind | implementation | recovered semantics |
|---:|---:|---|
| 0 | inline in `0x23730` | full-string ASCII case-insensitive equality |
| 1 | `0x12ad00` | ASCII case-insensitive prefix / starts-with |
| 2 | `0x12b474` | ASCII case-insensitive suffix / ends-with |
| 3 | `0x12ba10` | overlapping ASCII case-insensitive substring |
| 4 | inline in `0x23730` | full-string case-sensitive equality |
| 5 | `0x127a78` | overlapping case-sensitive substring |
| 6 | `0x128038` | case-sensitive suffix / ends-with |
| 7 | `0x128364` | optimized case-sensitive substring; same observable predicate as kind 5 |
| 8 | inline | argument zero is non-null and non-empty; descriptor is ignored |

Important boundary behavior:

- all recovered helpers reject null inputs;
- `0x12ad00`, `0x12b474`, and `0x128038` accept an empty marker/suffix;
- `0x12ba10("", "")` is false because its outer candidate loop requires a
  non-NUL value byte;
- `0x12ba10("x", "")` is true;
- ASCII folding affects only `A..Z`.
- `0x128364` uses a byte-indexed table and four-byte packing, but static
  instruction interpretation through the kind-seven caller state matches the
  case-sensitive substring result, including empty-marker behavior;
- kind eight returns false for null/empty argument zero and true for non-empty
  argument zero even when the descriptor pointer is null.

Evidence and regression:

```text
.omx/static-audit-20260713/analyze_descriptor_predicates_23730.py
.omx/static-audit-20260713/disasm-23730-24444.txt
.omx/static-audit-20260713/disasm-128038-128364.txt
.omx/static-audit-20260713/disasm-12ad00-12b474.txt
.omx/static-audit-20260713/disasm-12b474-12ba10.txt
.omx/static-audit-20260713/disasm-12ba10-12c12c.txt
native-reimplementation/recovered_primitives.cpp
```

The analyzer interprets the saved ARM64 instructions; it does not load or
execute the target shared object.
