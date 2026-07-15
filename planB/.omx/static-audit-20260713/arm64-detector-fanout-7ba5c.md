# ARM64 `0x7ba5c..0x7bb98` detector fanout

This FDE is a straight-line orchestration wrapper, not a detector body. It
preserves all four arguments and calls these ARM64 stages in order:

```text
40c70 40ffc 418e8 421dc 43104 439a8 442ec
44c38 44db0 456b8 47788 47f94 490f0 4b020
```

Every call receives the same four original values. Callee return registers are
ignored. The wrapper ends with `mov w0,wzr`, so its return is always zero.

x86_64 `0x7c1f8..0x7c32f` independently confirms the same argument-forwarding
and zero-return pattern, but contains 17 stages rather than 14. This is an
ABI-specific detector-set difference; the authoritative ARM64 rewrite keeps
the exact 14-stage list.

`runRecoveredDetectorFanout7ba5c()` directly represents the wrapper with a
fixed-size stage array. Its regression proves 14 calls, unchanged arguments,
and unconditional zero return. Individual detector bodies remain separately
tracked FDEs and are not claimed recovered by this wrapper result.

Repeatable check:

```bash
python3 .omx/static-audit-20260713/analyze_detector_fanout_7ba5c.py
```
