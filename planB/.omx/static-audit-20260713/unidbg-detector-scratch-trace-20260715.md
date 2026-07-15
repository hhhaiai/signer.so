# Isolated Unidbg detector-scratch trace — 2026-07-15

## Boundary

- Local authorized ARM64 `libsigner.so` only.
- Maven offline mode (`-o`).
- Structured `DeviceProfile` explicitly refuses `127.0.0.1:27042`.
- No external host or Internet access.
- `CodeHook` reads registers and emulated memory only; it does not override a
  register, return value, branch, JNI result, or target byte.

Command:

```bash
ADJUST_NATIVE_DETECTOR_SCRATCH_TRACE=1 \
  mvn -o -q \
  -Dtest=SignerEngineNativeIntegrationTest#structuredDeviceProfileRunsRealNativeV4AndV5 \
  test
```

Result:

```text
exit code: 0
V4 first call: pass
V4 repeat: pass
V5 call: pass
```

## `0xb21b4` live observations

All three calls produced the same ordered trace:

```text
producer entry: caller libsigner.so+0xf3c0

int-field entry:
  caller              libsigner.so+0x8d568
  field               widthPixels
  incoming status     0
  output              scratch+0x60
int-field return:
  status              0
  value               1440 / 0x5a0

int-field entry:
  caller              libsigner.so+0x8c324
  field               heightPixels
  incoming status     0
  output              scratch+0x64
int-field return:
  status              0
  value               3120 / 0x0c30

producer return:
  status              0
  scratch+0x60        0x5a0
  scratch+0x64        0x0c30
  stringCount         1
```

This corroborates:

```text
scratch+0x60 = displayWidth
scratch+0x64 = displayHeight
runtime order = widthPixels, then heightPixels
```

## `0xbce98` live observations

Before those two field reads, all three runs entered `0xbce98` from producer
return address `0x8e9cc`:

```text
incoming status = 0
resources       = non-null
output initial  = 0
returned type   = android/util/DisplayMetrics
final status    = 0
```

The returned handle was then passed to both `0xb21b4` calls. Combined with the
cross-ABI decoded contract
`getDisplayMetrics()Landroid/util/DisplayMetrics;`, this closes the object-flow
edge from Resources to the recovered width/height fields.

## `0xa8978` live observations

The same three runs entered `0xa8978` from producer return address `0x8da64`:

```text
incoming status = 0
object          = non-null Java collection-like object
output initial  = 0
output result   = 1
final status    = 0
```

The final scratch simultaneously contained `stringCount=1` and exactly one
sensor pair. Combined with the cross-ABI decoded method contract `size()I`,
this corroborates that `0xa8978` reads the collection count used by the sensor
loop.

## `0xa948c` live observations

Immediately after the `size()=1` result, all three runs entered `0xa948c` and
returned through producer address `0x8e35c`:

```text
incoming status = 0
collection      = non-null
index           = 0
output initial  = 0
returned type   = android/hardware/Sensor
final status    = 0
```

Together with the cross-ABI decoded contract
`get(I)Ljava/lang/Object;`, this corroborates that `0xa948c` retrieves the
sensor object for each collection index before the producer reads its
name/vendor fields.

## Sensor service and collection pipeline

All three runs observed the complete object chain:

```text
0xb5828 Context.getSystemService:
  static field    SENSOR_SERVICE
  returned type   android/hardware/SensorManager
  final status    0

0xc0180 SensorManager.getSensorList:
  type argument   -1
  returned type   java/util/ArrayList
  final status    0

0xa8978 size()     1
0xa948c get index  0
0xa948c type       android/hardware/Sensor

0xbea74 getName    LSM6DSO
0xbf5fc getVendor  STMicroelectronics
```

Verbose JNI tracing separately confirmed `0xb5828` executes
`FindClass -> GetMethodID -> GetStaticFieldID -> GetStaticObjectField ->
CallObjectMethod` in that order.

## Resources and display pipeline

```text
0xbb5a0 Resources.getSystem:
  returned type   android/content/res/Resources
  final status    0

0xbce98 Resources.getDisplayMetrics:
  returned type   android/util/DisplayMetrics
  final status    0
```

The returned DisplayMetrics handle is the exact object subsequently passed to
the `widthPixels` and `heightPixels` reads.

## Producer output envelope

The same structured profile produced the following fixed fields on all three
runs:

```text
+0x00 bullhead
+0x08 LGE
+0x10 google
+0x18 Nexus 5X
+0x20 bullhead
+0x30 google/bullhead/bullhead:6.0/MDA89E/2296692:user/release-keys
+0x38 user
+0x40 bullhead
+0x50 android-build
```

The sole dynamic pair was:

```text
strings[0].value             = LSM6DSO
strings[0].secondaryValue08  = STMicroelectronics
stringCount                  = 1
```

The result confirms that `0x8746c` materializes Build-like fixed strings,
display dimensions, and sensor name/vendor pairs into the recovered `0x878`
scratch layout. Exact names for the duplicate `bullhead` fields still require
static call-site attribution or a differential profile with unique Build-field
values; they are not guessed from this one trace.

## Evidence role

This trace is auxiliary evidence. Function recovery status remains gated by:

1. ARM64 FDE and instruction proof;
2. x86_64 cross-ABI proof;
3. source-level C++ behavior;
4. regression entry;
5. dedicated static verifier and synchronized coverage/docs.
