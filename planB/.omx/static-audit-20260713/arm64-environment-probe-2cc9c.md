# ARM64 `0x2cc9c..0x2e1d4` minical/vcloud/Scorpio property probe

## FDE and caller

| ABI | range | caller behavior |
|---|---|---|
| ARM64 | `0x2cc9c..0x2e1d4` | `0xfb24` calls the probe; true reaches correction `0x2c` at `0xf9dc..0xf9e0` |
| x86_64 | `0x2d13c..0x2dba0` | equivalent five-record batch and `setne` return |

The function's only direct non-runtime callee is the recovered descriptor batch
matcher (`0x24444` on ARM64, `0x2702f` on x86_64).  ARM64 additionally calls
the shared byte compare-exchange helper `0x139800` once for each protected
string.

## Cross-ABI XOR-once strings

| role | ARM64 file offset/key | x86_64 file offset/key | plaintext |
|---|---|---|---|
| property 0 | `0x13b690 / 0xa0` | `0x134060 / 0xb5` | `ro.product.manufacturer` |
| property 1 | `0x13b8b0 / 0xf2` | `0x134280 / 0xf4` | `ro.product.vendor.manufacturer` |
| property 2 | `0x13b6b0 / 0x5a` | `0x134080 / 0x99` | `ro.product.model` |
| marker 0/1 | `0x13b8d0 / 0x66` | `0x1342a0 / 0x0e` | `minical` |
| marker 2/3 | `0x13b8d8 / 0xf1` | `0x1342a8 / 0x4d` | `vcloud` |
| property 3 | `0x13b8e0 / 0x4f` | `0x1342b0 / 0x57` | `ro.product.vendor.model` |
| property 4 | `0x13b900 / 0x26` | `0x1342d0 / 0xba` | `ro.build.display.id` |
| marker 4 | `0x13b918 / 0x9a` | `0x1342e8 / 0xac` | `Scorpio_rt OS` |

`minical` is the exact binary plaintext; it is not `minicap`.

Both ABIs contain eight byte compare-exchange lock acquisitions.  ARM64 has
eight matching release-store operations (`stlrb wzr`) after decode/publication.
The portable C++ represents the already-decoded source-level constants; the
dedicated verifier retains the original XOR keys, offsets and lock counts.

## Record layout and result

`0x2e0e4` clears the record area and `0x2e11c` passes record count five.  Every
record is `0x100` bytes, has `descriptorCount = 1`, and uses predicate kind `3`
(ASCII case-insensitive substring):

| record | property | marker |
|---:|---|---|
| 0 | `ro.product.manufacturer` | `minical` |
| 1 | `ro.product.vendor.manufacturer` | `minical` |
| 2 | `ro.product.model` | `vcloud` |
| 3 | `ro.product.vendor.model` | `vcloud` |
| 4 | `ro.build.display.id` | `Scorpio_rt OS` |

Terminal ARM64 flow:

```text
0x2e17c  uint16 match count = 0
0x2e180  call 0x24444(records, 5, &matchCount)
0x2e184  load uint16 match count
0x2e194  return matchCount != 0
```

x86_64 independently uses count five, calls `0x2702f`, compares the same
uint16 output with zero, and returns through `setne`.

## C++ parity surface

```text
native-reimplementation/recovered_primitives.cpp:
  runRecoveredMinicalVcloudScorpioProbe2cc9c
  recoveredMinicalVcloudScorpioProbe2cc9cRegression
```

The regression covers empty/all-miss input, each of the three marker families,
mixed ASCII case, near-miss strings, simultaneous matches, exact five-property
read order, zeroed `0x5c` property buffers, ignored property-reader return values
and the final `uint16 != 0` boolean rule.

## Isolated original-SO corroboration

```text
unidbg-adjust-runner/src/test/java/local/
  MinicalVcloudScorpioProbeNativeIntegrationTest.java
```

Observation-only hooks read:

```text
0x2cc9c  probe entry
0x2e198  w0 after cset
0xf9e0   correction helper call with w1 == 0x2c
```

The final JDK 17 / Maven offline run uses two isolated profiles:

```text
Google ordinary properties:
  entry 1, result 0, correction 0x2c calls 0

Acme MiNiCaL Device manufacturer:
  entry 1, result 1, correction 0x2c calls 1
```

Result: `2 tests / 0 failures / 0 errors / 0 skipped`.

The earlier three-profile attempt hit the known macOS ARM64 Unicorn native
crash while starting a third emulator.  The final two-profile class stays below
that lifecycle boundary.  No hook modifies registers, return values, branches,
JNI objects or target bytes.

## Repeatable checks

```bash
python3 .omx/static-audit-20260713/analyze_environment_probe_2cc9c.py
./native-reimplementation/build-and-test.sh

JAVA_HOME=$(/usr/libexec/java_home -v 17) \
  mvn -o -Dtest=MinicalVcloudScorpioProbeNativeIntegrationTest test
```
