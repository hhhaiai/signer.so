# ARM64 `0x8746c` detector-scratch producer — static recovery

## Current status

```text
ARM64:  0x8746c..0x8f56c, size 0x8100
x86_64: 0x88475..0x93f86, size 0xbb11
coverage status: recovered
JNI reachable: yes
```

This FDE is now `recovered`. The call surface, every direct internal helper,
all thirteen property materialization stages, the non-property sensor/display
orchestration and the property-before-sensor composition are represented in
C++. A dedicated 231-state x86_64 dispatcher parser plus ARM64 corroboration
binds every helper failure publication, and the sole caller's final `0x8fb44`
destructor envelope is covered for success and every failure class.

## Sole caller and signature

The sole caller zeroes a `0x878`-byte stack object before calling:

```text
ARM64  0xf36c  scratch = sp+0x38
       0xf374  size = 0x878
       0xf3a8  memset(scratch,0,0x878)
       0xf3ac  x2 = scratch
       0xf3bc  bl 0x8746c

x86_64 0x1316a scratch = rsp+0x38
       0x1316f size = 0x878
       0x13176 memset(scratch,0,0x878)
       0x13185 rdx = scratch
       0x1318a call 0x88475
```

The recovered input shape is therefore:

```cpp
uint32_t producer(JNIEnv* env, jobject context,
                  RecoveredDetectorScratch868b4* scratch);
```

The return value is stored into the caller's status and tested for zero.

## Cross-ABI direct-call map

| ARM64 | x86_64 | Calls | Current role/status |
|---:|---:|---:|---|
| `0x8f56c` | `0x93f86` | 1 | recovered scratch owned-pair appender |
| `0x92b24` | `0x96ae0` | 2 | recovered JNI GetStringUTFChars acquisition |
| `0x95020` | `0x98081` | 2 | recovered ReleaseStringUTFChars guard |
| `0xa8978` | `0xa469c` | 1 | recovered JNI `size()I` int-method reader |
| `0xa948c` | `0xa4cd9` | 1 | recovered JNI `get(int)` object-method reader |
| `0xb21b4` | `0xaa362` | 2 | recovered JNI int-field reader for `heightPixels` / `widthPixels` |
| `0xb5828` | `0xac4d5` | 1 | recovered JNI `Context.getSystemService(static field)` getter |
| `0xbb5a0` | `0xafb26` | 1 | recovered JNI static `Resources.getSystem()` getter |
| `0xbce98` | `0xb0994` | 1 | recovered JNI `Resources.getDisplayMetrics()` getter |
| `0xbea74` | `0xb1a13` | 1 | recovered JNI `Sensor.getName()` getter |
| `0xbf5fc` | `0xb20c2` | 1 | recovered JNI `Sensor.getVendor()` getter |
| `0xc0180` | `0xb278e` | 1 | recovered JNI `SensorManager.getSensorList(int)` getter |
| `0xd4678` | `0xc1a02` | 13 | recovered Android system-property dispatcher |

ARM64 additionally calls recovered acquire-byte CAS helper `0x139800` sixteen
times.  x86_64 contains sixteen inlined `lock cmpxchg` sites.  This proves a
cross-ABI set of sixteen process-global once-decoded string/config slots.

## Recovered property-materialization subpipeline

Both ABIs contain exactly:

```text
13 system-property dispatcher calls
13 malloc call sites
1 scratch pair-appender call
```

Cross-ABI static decoding plus an observation-only unique-value profile has now
closed the exact identifiers and field map:

```text
+0x00 ro.product.name
+0x08 ro.product.manufacturer
+0x10 ro.product.brand
+0x18 ro.product.model
+0x20 ro.product.device
+0x28 ro.build.display.id
+0x30 ro.build.fingerprint
+0x38 ro.build.type
+0x40 ro.hardware
+0x48 ro.bootloader
+0x50 ro.build.user
+0x58 ro.build.host
+0x68 ro.product.cpu.abilist
```

All thirteen reads reuse one zeroed `0x60` stack buffer. Each value is measured,
copied into `malloc(length+1)`, NUL-terminated and published one stage later;
the final `+0x68` pointer is published after the last read. Every allocation
failure clears the current field and returns status `2` while preserving prior
publications. The C++ implementation receives values through a caller-supplied
`readProperty(name, output)` callback; it contains no device-value defaults.

Evidence:

```text
.omx/static-audit-20260713/analyze_detector_scratch_property_pipeline_8746c.py
.omx/static-audit-20260713/arm64-detector-scratch-property-pipeline-8746c.md
.omx/static-audit-20260713/unidbg-detector-scratch-unique-properties-raw.log
```

## Recovered sensor/display subpipeline

Both ABIs now prove:

```text
getSystemService(SENSOR_SERVICE)
getSensorList(-1)
size()
signed jint index < size
get(index)
getName -> GetStringUTFChars
getVendor -> GetStringUTFChars
0x8f56c append
terminal sensor cleanup
Resources.getSystem -> getDisplayMetrics
widthPixels -> scratch+0x60
heightPixels -> scratch+0x64
DisplayMetrics/Resources cleanup
```

ARM64 selects the loop with `cmp w27,w14` and `csel ... lt`; x86_64 uses
`cmp ecx,[size]` and `cmovl`. The C++ model therefore uses `int32_t`, with
regressions for `size 0/-1/1/2`. It also covers service/list/size/get/name/
name-UTF/vendor/vendor-UTF/appender failures, appender statuses `2/0x26`, and
resources/display/width/height failures.

The two-sensor trace proves there is no per-iteration cleanup. Only the final
name/vendor UTF pointers and final Sensor/name/vendor refs are released after
the loop, in the order name UTF, vendor UTF, SensorManager, List, last Sensor,
last name and last vendor; display work begins only after that terminal sensor
cleanup. A separate 128-sensor run reaches index 127, receives appender status
`0x26` with count fixed at 127, cleans only the last temporary handles and
skips Resources/display entirely.

Evidence:

```text
.omx/static-audit-20260713/analyze_detector_sensor_display_pipeline_8746c.py
.omx/static-audit-20260713/arm64-detector-sensor-display-pipeline-8746c.md
.omx/static-audit-20260713/unidbg-detector-scratch-two-sensor-loop-raw.log
.omx/static-audit-20260713/unidbg-detector-scratch-128-sensor-boundary-raw.log
```

## Dependency and ownership boundary

The adjacent ownership primitives are now closed:

```text
0x8f56c  appends at most 127 owned string pairs and preserves slot 127 sentinel
0x8fb44  destroys fixed owned fields and pair slots through the first sentinel
```

`runRecoveredDetectorScratchProducer8746c()` now composes the recovered paths
in the proven order: all thirteen properties first, then sensor/display only
when the property status is zero. Its regression covers full success, a fifth
property-allocation failure that skips all sensor work, and a second-pair
appender `0x26` failure that preserves all properties and the first pair.

The closure verifier proves all thirteen helper failure/success state pairs and
their alias chains. Service failure is normalized to `0x24`; width/height field
failure is normalized to `0x1d`; list/size/get/name/name-UTF/vendor/vendor-UTF,
appender, Resources and DisplayMetrics failures preserve the helper status.
Both status cells reach the final x86_64 return local and ARM64 returns the
corresponding `w20`. The post-appender index increment occurs after success and
failure selection. The native-destructor regression covers all 13 property
allocation failures, nine first-sensor failure classes, second-pair `0x26`,
four display failure classes and success. It confirms the eight released fixed
fields and published pairs are cleared while `+28/+40/+48/+58/+68`, count and
display fields retain the exact compatibility state.

Evidence:

```text
.omx/static-audit-20260713/analyze_detector_scratch_failure_publication_8746c.py
.omx/current-8746c-destructor-envelope-build.log
.omx/current-8746c-closure-sanitizer.log
```

## Auxiliary isolated dynamic evidence

An offline Unidbg structured profile completed V4, V4-repeat and V5 runs while
an observation-only hook captured the producer output. Every run returned
status zero and produced:

```text
scratch+0x60 displayWidth  = 1440
scratch+0x64 displayHeight = 3120
scratch+0x870 stringCount  = 1
strings[0]                 = LSM6DSO | STMicroelectronics
0xa8978 size() result      = 1, status = 0
0xa948c get(0) result      = android/hardware/Sensor, status = 0
0xbce98 result             = android/util/DisplayMetrics, status = 0
0xb5828 result             = android/hardware/SensorManager, status = 0
0xbb5a0 result             = android/content/res/Resources, status = 0
0xc0180 getSensorList(-1)  = one-element ArrayList, status = 0
0xbea74 / 0xbf5fc          = LSM6DSO / STMicroelectronics
```

The original default profile and a unique-value differential profile both ran
V4, V4-repeat and V5 successfully. The unique-value run confirms all thirteen
field identities above, including previously opaque `+0x28/+0x48/+0x58/+0x68`.
Those values were temporary trace inputs and were removed from the Java test
source after capture.

## Artifacts

```text
.omx/static-audit-20260713/disasm-8746c-8f56c.txt
.omx/static-audit-20260713/disasm-x86-88475-93f86.txt
.omx/static-audit-20260713/analyze_detector_scratch_producer_8746c_progress.py
.omx/static-audit-20260713/analyze_detector_scratch_property_pipeline_8746c.py
.omx/static-audit-20260713/arm64-detector-scratch-property-pipeline-8746c.md
.omx/static-audit-20260713/analyze_detector_sensor_display_pipeline_8746c.py
.omx/static-audit-20260713/analyze_detector_scratch_failure_publication_8746c.py
.omx/static-audit-20260713/arm64-detector-sensor-display-pipeline-8746c.md
.omx/static-audit-20260713/analyze_jni_int_field_reader_b21b4.py
.omx/static-audit-20260713/analyze_jni_size_method_reader_a8978.py
.omx/static-audit-20260713/analyze_jni_indexed_object_method_reader_a948c.py
.omx/static-audit-20260713/analyze_jni_display_metrics_getter_bce98.py
.omx/static-audit-20260713/analyze_detector_jni_object_pipeline.py
.omx/static-audit-20260713/analyze_jni_system_service_getter_b5828.py
.omx/static-audit-20260713/unidbg-detector-scratch-trace-20260715.md
```

The progress verifier checks FDE/caller/signature, cross-ABI helper mapping,
sixteen once-init locks, thirteen property/malloc stages, the appender edge and
the now-fully-recovered direct-helper dependency set. The two `0xb21b4`
calls are separately proven as `heightPixels` / `widthPixels` JNI int reads;
the `0xa8978` call is a fixed Java `size()I` read, and `0xa948c` is the paired
`get(int)` object read. Recovered `0xbce98` supplies the exact DisplayMetrics
object consumed by the two int-field reads.
The system-service, sensor-list, sensor name/vendor and static Resources
helpers are also closed; remaining work is the producer's own flattened
allocation/publication/cleanup state machine rather than an unknown callee or
an absent source-level composition.
