# ARM64 CPU-feature decoder `0x1398cc..0x139d04`

## Scope and boundary

This FDE is the callee of the already recovered constructor wrapper at
`0x139d04`.  It converts a tagged HWCAP word, optional HWCAP2 descriptor and,
on one branch, five `ID_AA64*` register values into the process-global
64-bit CPU-feature word at `0x146bb8`.

The C++ recovery is deliberately portable and caller-driven.  It does not read
the host aux vector, Android properties or host CPU registers.  Every runtime
value has a separate `Provided` flag, so a valid zero register value is not
silently substituted for an omitted field.

Fixed items retained in source are algorithm/protocol constants rather than
device observations:

```text
tag bit                         taggedHwcap bit 62
system-register branch         HWCAP bit 11
descriptor HWCAP2 slot         descriptor +0x10 / element 2
process-global feature address original SO 0x146bb8 (evidence only)
final unconditional feature    bit 58 / 0x0400000000000000
```

## Native entry and lazy input consumption

```text
0x1398dc  load global feature word
0x1398e4  zero -> decode; nonzero -> return unchanged
0x1398f8  test taggedHwcap bit 62
0x1398fc  tag clear: HWCAP2 = 0
0x139904  tag set:   HWCAP2 = descriptor[2]
0x139b60  test HWCAP bit 11
```

The C++ input contract mirrors that lazy behavior:

1. `publishedFeatures` is required first.  A nonzero value returns without
   requiring any other field.
2. `taggedHwcap` is required only on the cold path.
3. `auxDescriptor` is required only if bit 62 is set; otherwise HWCAP2 is the
   native zero value and no descriptor is consumed.
4. `ID_AA64PFR1_EL1`, `ID_AA64PFR0_EL1`, `ID_AA64ISAR0_EL1` and
   `ID_AA64ISAR1_EL1` are required only if HWCAP bit 11 is set.
5. `ID_AA64ZFR0_EL1` is required only if PFR0 bits 32..35 are nonzero, matching
   the conditional `mrs` at `0x139c30`.

Missing required input returns a typed adapter status before any recovered
global publication; it is never converted to a fabricated zero-valued device
snapshot.

## Publication order

The native function has five store instructions, not one final assignment:

```text
0x139af8  conditional early HWCAP/HWCAP2 publication
0x139b9c  HWCAP-bit-11-clear path, conditional HWCAP publication
0x139bec  system-register path, conditional PFR1 publication
0x139c88  system-register path, conditional ISAR1 publication
0x139cd4 / 0x139cf0  final publication including feature bit 58
```

The paths are mutually constrained, so one invocation produces at most four
stores.  `RecoveredCpuFeatureDecoderOutput1398cc::publications` preserves the
exact observed store order and `publishedFeatures` retains the last stored
word.  A nonzero incoming global produces no new publication.

## System-register field mapping

The HWCAP-bit-11 branch reads fields in this order:

```text
ID_AA64PFR1_EL1
ID_AA64PFR0_EL1
ID_AA64ZFR0_EL1  only when PFR0[35:32] != 0
ID_AA64ISAR0_EL1
ID_AA64ISAR1_EL1
```

Important decoded conditions locked by the direct C++ regression are:

| Input field | Condition | Added internal feature |
|---|---|---:|
| PFR1 bits 8..11 | nonzero | bit 43 and intermediate publish |
| PFR1 bits 4..7 | exactly 1 | bit 48 |
| PFR1 bits 24..27 | exactly 2 | bit 57 |
| PFR0 bits 16..19 | exactly `0xf` | bits 8 and 9 |
| ZFR0 bits 0..3 | 0 | bit 30 |
| ZFR0 bits 0..3 | 1 | bit 36 |
| ZFR0 bits 20..23 | nonzero | bit 31 |
| ISAR0 bits 32..35 | nonzero | bit 13 |
| ISAR1 bits 0..3 | nonzero | bit 18 |
| ISAR1 bits 20..23 | nonzero | bit 22 and intermediate publish |
| ISAR1 bits 40..43 | exactly 2 | bit 47 |
| ISAR1 bits 44..47 | nonzero | bit 27 |
| ISAR1 bits 60..63 | 1 | bit 51 |
| ISAR1 bits 60..63 | 2 | bits 51..52 |
| ISAR1 bits 60..63 | greater than 2 | bits 51..53 |

The non-system-register branch additionally proves the combined condition at
`0x139bbc..0x139bd4`: internal feature bit 36 is added only when HWCAP2 bit 1
and HWCAP bit 22 are both set.

## C++ symbols

```text
RecoveredCpuFeatureDecoderStatus1398cc
RecoveredCpuFeatureDecoderInput1398cc
RecoveredCpuFeatureDecoderOutput1398cc
runRecoveredCpuFeatureDecoder1398cc
recoveredCpuFeatureDecoder1398ccRegression
```

The regression covers missing/present distinction, nonzero-global early
return, descriptor-tag behavior, tag-clear HWCAP2 zeroing, both HWCAP-bit-11
branches, ordered intermediate stores, a dense exact vector and boundary
values for every decoded `ID_AA64*` field.

## Verification

```bash
python3 .omx/static-audit-20260713/analyze_cpu_feature_decoder_1398cc.py
clang++ -std=c++17 -Wall -Wextra -Werror \
  -fsyntax-only native-reimplementation/recovered_primitives.cpp
./native-reimplementation/build-and-test.sh
```

Coverage effect:

```text
all ARM64 FDEs: 319 recovered / 0 partial / 69 unknown
JNI-reachable:  276 recovered / 0 partial / 45 unknown
```

This function is not statically reachable from the two JNI exports, so it only
changes the all-file count.
