# ARM64 `0x8746c` sensor/display subpipeline

## Scope and status

This artifact closes the non-property success-path orchestration and its
caller-visible failure/cleanup model inside:

```text
ARM64:  0x8746c..0x8f56c
x86_64: 0x88475..0x93f86
```

It does **not** by itself change the parent FDE from `unknown`: the final
coverage transition remains gated by a single composed producer proof that
joins the already recovered 13-property materializer, this sensor/display
subpipeline, every flattened failure publication and the exact original
destructor ownership envelope.

## Cross-ABI sensor loop

The two ABIs execute the same semantic chain:

```text
Context.getSystemService(SENSOR_SERVICE)
SensorManager.getSensorList(-1)
List.size()

for (signed jint index = 0; index < signed jint size; ++index) {
    Sensor sensor = List.get(index)
    String name = sensor.getName()
    {name UTF pointer, name UTF length} = GetStringUTFChars(name)
    String vendor = sensor.getVendor()
    {vendor UTF pointer, vendor UTF length} = GetStringUTFChars(vendor)
    status = appendOwnedPair(name, nameLength, vendor, vendorLength)
    // The native post-appender state increments index before selecting the
    // success continuation or the nonzero-status cleanup path.
}
```

ARM64 call sites:

```text
0x8af24  bl 0xb5828  getSystemService
0x8cc60  bl 0xc0180  getSensorList(-1)
0x8da60  bl 0xa8978  size()
0x8e358  bl 0xa948c  get(index)
0x8bf60  bl 0xbea74  getName()
0x8ad3c  bl 0x92b24  name UTF acquisition
0x8ca74  bl 0xbf5fc  getVendor()
0x8ec34  bl 0x92b24  vendor UTF acquisition
0x8bccc  bl 0x8f56c  owned pair append
```

x86_64 independently contains the matching helpers at `0xac4d5`, `0xb278e`,
`0xa469c`, `0xa4cd9`, `0xb1a13`, `0xb20c2`, two calls to `0x96ae0`, and the
pair appender call to `0x93f86`.

### Signed loop condition

The collection size and index are Java `jint` values, not unsigned counts.

```text
ARM64  0x8ecd4  cmp  w27,w14
       0x8ece0  csel x6,x16,x15,lt

x86_64 0x9124e  cmp   ecx,DWORD PTR [rax]
       0x91264  cmovl rdx,rax
```

The C++ model therefore uses `std::int32_t` for both values. A prior
`std::uint32_t` draft was incorrect for a negative `size()` result and could
have entered an effectively unbounded loop. Direct regressions cover
`size == 0`, `size == -1`, `size == 1` and `size == 2`.

## Terminal sensor cleanup and overwrite behavior

Both ABIs contain exactly two UTF release helper calls and seven
producer-owned `DeleteLocalRef` calls. The ARM64 two-sensor observation maps
the first five local-ref sites and their order:

```text
0x8a84c  ReleaseStringUTFChars(last name)
0x8d114  ReleaseStringUTFChars(last vendor)
0x8e158  DeleteLocalRef(SensorManager)
0x8dbfc  DeleteLocalRef(List)
0x8cd38  DeleteLocalRef(last Sensor)
0x8c22c  DeleteLocalRef(last name String)
0x8dde0  DeleteLocalRef(last vendor String)
```

The display stage then runs and ends with:

```text
0x8c754  DeleteLocalRef(DisplayMetrics)
0x8b53c  DeleteLocalRef(Resources)
```

x86_64 has seven direct `[JNIEnv table + 0xb8]` calls at:

```text
0x8d46e  0x8f229  0x8f600  0x8fc72
0x90303  0x90cd9  0x91193
```

The two-sensor trace proves there is no per-iteration release between pair
count `1` and pair count `2`. The temporary Sensor/name/vendor refs and both
UTF pointers from iteration zero are overwritten. Only the final iteration's
temporaries are explicitly cleaned.

An independent 128-sensor boundary run proves the appender limit in the full
producer context:

```text
size()                         128
get(index) calls               128
pair append attempts           128
index 126 result               status 0, count 127
index 127 result               status 0x26, count remains 127
terminal UTF releases          2
terminal sensor local deletes  5
Resources/display calls        0
producer return                status 0x26
display width/height           0 / 0
```

This corroborates that capacity failure is propagated without entering the
display stage and that cleanup still targets only iteration 127's temporary
handles. Slots `0..126` remain published; the appender's direct regression
separately proves slot 127 remains the all-null destructor sentinel.

This behavior is preserved in the strict-compatible C++ model. The separate
`RecoveredDetectorInputProfile8746c` adapter intentionally uses a hardened
all-owned-data cleanup and must not be confused with the native compatibility
path.

## Display stage

After terminal sensor cleanup and only while status remains zero:

```text
0x8c2a0  bl 0xbb5a0  Resources.getSystem()
0x8e9c8  bl 0xbce98  Resources.getDisplayMetrics()
0x8d564  bl 0xb21b4  widthPixels  -> scratch+0x60
0x8c320  bl 0xb21b4  heightPixels -> scratch+0x64
```

DisplayMetrics is deleted before Resources. A nonzero sensor status skips the
entire display stage; a display-stage failure preserves any already appended
sensor pairs and cleans the local references acquired up to that point.

## C++ implementation and regression envelope

Implementation:

```text
native-reimplementation/recovered_primitives.cpp
  RecoveredDetectorSensorDisplayOperations8746c
  runRecoveredDetectorSensorDisplayPipeline8746c
  recoveredDetectorSensorDisplayPipeline8746cRegression
  RecoveredDetectorScratchProducerOperations8746c
  runRecoveredDetectorScratchProducer8746c
  recoveredDetectorScratchProducer8746cRegression
```

The composed producer executes the 13-property materializer first, returns a
property allocation failure without entering the JNI sensor path, and otherwise
forwards the same scratch into the recovered sensor/display subpipeline. Its
regression covers full success, property-stage early failure and a later
appender `0x26` failure with already published properties and one retained pair.

The direct regression covers:

```text
two-sensor success and exact event order
size 0, -1, 1 and 2
service/list/size failures
get/name/name-UTF/vendor/vendor-UTF failures
appender status 2 and 0x26
last-iteration-only UTF/local-ref cleanup
resources/display/width/height failures
width-before-height publication
DisplayMetrics-before-Resources deletion
preservation of already appended pairs on later failure
```

Machine verifier:

```text
.omx/static-audit-20260713/analyze_detector_sensor_display_pipeline_8746c.py
```

Dynamic evidence:

```text
.omx/static-audit-20260713/unidbg-detector-scratch-two-sensor-loop-raw.log
.omx/static-audit-20260713/unidbg-detector-scratch-128-sensor-boundary-raw.log
.omx/current-two-sensor-cleanup.stderr
```

The hooks are observation-only: they read registers, handles and emulated
memory and do not alter target bytes, branches, JNI values or return values.

## Security/ownership note

For `N > 1`, the first `N-1` sensor name/vendor UTF acquisitions are never
released and the first `N-1` Sensor/name/vendor local references are not
explicitly deleted. Local references are normally reclaimed when the native
frame returns, but they still create intra-call local-reference pressure. An
unreleased copied UTF buffer can persist as native-memory leakage. A hardened
product implementation should clean every iteration; the compatibility model
retains the original behavior for parity.
