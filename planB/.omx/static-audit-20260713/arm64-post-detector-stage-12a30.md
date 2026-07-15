# ARM64 `0x12a30..0x13000` post-detector aggregator

This FDE receives the populated detector scratch object in `x0` and the native
context in `x1`.  Static interpretation of the flattened ARM64 state machine
recovers thirteen boolean predicate calls in this exact order:

```text
4d9bc 59658 5a8e0 5c6d8 5f900 615d8 6a4e0
6c590 6dbbc 6f758 76f2c 77f7c 78f68
```

Every predicate receives the original scratch pointer.  A true low bit stops
the chain immediately, calls correction writer `0x13548c` with code `0x21`,
and sets context flag bit zero.  A complete miss performs neither action.
Both paths finally OR context flag bit 33 (`0x0000000200000000`) and return.

`runRecoveredPostDetectorStage12a30` is the direct orchestration equivalent.
The predicate bodies remain separately inventoried and are not implicitly
claimed by closing this wrapper.

Machine-checkable reproduction:

```bash
python3 .omx/static-audit-20260713/analyze_post_detector_stage_12a30.py
```

The interpreter proves the all-false call order and, for each of the thirteen
possible first-hit positions, verifies the exact short circuit, correction
argument, bit-zero mutation and unconditional bit-33 mutation.  The C++
regression covers miss, first, middle and last-hit cases.
