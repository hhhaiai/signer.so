# Ralph context: libsigner C++ equivalence

## Task statement

Statically recover every JNI-reachable behavior from
`adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so` and implement the
same logic in `native-reimplementation`, so equal inputs produce equal output,
including corrections, score, cryptographic envelope, metadata, failures and
cleanup behavior.

## Desired outcome

- Every JNI-reachable FDE is classified with address-backed evidence.
- All behavior required by the JNI call graph has direct C++ source coverage.
- Build, C++ regressions, sanitizer runs and frozen parity remain green.
- No completeness claim until the JNI-reachable unknown/partial inventory is
  closed or an evidence-backed non-semantic/runtime-only classification removes
  an entry from the implementation boundary.

## Known facts and evidence

- ARM64 target SHA-256:
  `8be033d3423258ac6975c17813eae0ee41c9c743f90ab40e40fa9c1c58eef371`.
- Current inventory: 388 FDEs; 321 JNI reachable; 124 recovered, 10 partial,
  187 unknown among JNI-reachable entries.
- Existing C++ oracle, ASan/UBSan, Maven compile and 14/14 parity were green at
  the prior checkpoint.
- `0x7ba5c`, `0x7bbb0`, `0x868b4`, `0x127a78`, `0x40c70`, `0x42eb0` and
  `0x44c38` have address-backed direct C++ models.
- Current detector targets are `0x40ffc` (`google_sdk`, correction `0x0d`) and
  `0x418e8` (`emulator`, correction `0x0e`), both reading scratch offset
  `+0x18` and updating score to `1.0f` on a match.

## Constraints

- Work only inside `/Users/sanbo/Desktop/api/qbdi`; do not use the network or
  external hosts/devices.
- Keep target-SO analysis static. It is acceptable to compile and run only the
  repository-owned C++/Java verification harnesses.
- Make surgical, evidence-backed changes and retain exact native edge behavior.
- User requested persistent execution until the full objective is met.
- Current developer policy forbids spawning sub-agents without an explicit
  user request, so this Ralph run proceeds in a single-agent lane.

## Unknowns and open questions

- Prove whether `0x40ffc` and `0x418e8` implement full equality or overlapping
  case-insensitive substring search, including their restart cursor behavior.
- Recover the remaining fanout bodies and shared helpers `0x23730`/`0x352d4`.
- Close `0xfce0` only after all reachable detector dependencies are recovered.

## Likely codebase touchpoints

- `native-reimplementation/recovered_primitives.cpp`
- `native-reimplementation/SO_FUNCTION_COVERAGE.md`
- `.omx/static-audit-20260713/generate_arm64_function_inventory.py`
- `.omx/static-audit-20260713/arm64-function-inventory.csv`
- `.omx/static-audit-20260713/disasm-40ffc-418d8.txt`
- `.omx/static-audit-20260713/disasm-418e8-421cc.txt`
- `.omx/state/reflection-cadence.json`
