# Detector producer JNI object pipeline — recovered helpers

## Recovered ranges

| ARM64 | x86_64 | Recovered role |
|---:|---:|---|
| `0xbb5a0..0xbc3ac` | `0xafb26..0xb02c7` | static `Resources.getSystem()` |
| `0xbea74..0xbf5fc` | `0xb1a13..0xb20c2` | `Sensor.getName()` |
| `0xbf5fc..0xc0180` | `0xb20c2..0xb278e` | `Sensor.getVendor()` |
| `0xc0180..0xc0d84` | `0xb278e..0xb2e55` | `SensorManager.getSensorList(int)` |

Every range has one producer caller and one cross-ABI FDE counterpart.

## Decoded contracts

```text
android/content/res/Resources
getSystem
()Landroid/content/res/Resources;

getName
getVendor
()Ljava/lang/String;

getSensorList
(I)Ljava/util/List;
```

The ARM64 and x86_64 images use different XOR keys but decode to identical
class names, method names and signatures.

## JNI behavior

### `Resources.getSystem()`

```text
FindClass              +0x030
GetStaticMethodID      +0x388
CallStaticObjectMethod +0x390
DeleteLocalRef         +0x0b8
```

- class/method failure: status `18`;
- call exception or null result: status `28`;
- class local ref is always released after successful `FindClass`;
- incoming nonzero status does not skip JNI and clears the result.

### `Sensor.getName()` / `Sensor.getVendor()`

Both functions share the same control-flow contract:

```text
GetObjectClass   +0x0f8
GetMethodID      +0x108
CallObjectMethod +0x110
DeleteLocalRef   +0x0b8
```

- null sensor: status `3`;
- class/method failure: status `18`;
- call exception or null String: status `28`;
- returned String local ref is transferred to the caller;
- class local ref is deleted, then nonzero final status clears output.

### `SensorManager.getSensorList(int)`

This function has the same four JNI operations, but its status contract is
different:

- null SensorManager: status `3`;
- class, method, call exception, or null List: status `18`;
- status `28` is absent from both ABI implementations;
- the signed 32-bit type is forwarded unchanged; the producer passes `-1`.

## Producer object/data flow

```text
Context.getSystemService(SENSOR_SERVICE)
  -> SensorManager
  -> getSensorList(-1)
  -> List
  -> size()
  -> get(index)
  -> Sensor
  -> getName() / getVendor()
  -> scratch owned pair

Resources.getSystem()
  -> Resources.getDisplayMetrics()
  -> widthPixels / heightPixels
  -> scratch+0x60 / scratch+0x64
```

## Dynamic corroboration

An offline, observation-only Unidbg run completed V4, V4-repeat and V5. Every
run observed:

```text
getSensorList type = -1
list size          = 1
sensor index       = 0
sensor name        = LSM6DSO
sensor vendor      = STMicroelectronics
Resources type     = android/content/res/Resources
DisplayMetrics     = android/util/DisplayMetrics
width / height     = 1440 / 3120
```

The hooks did not modify registers, branches, return values, JNI objects or
target bytes. Failure states remain proven by static cross-ABI control flow and
C++ regressions.

## Evidence

```text
.omx/static-audit-20260713/analyze_detector_jni_object_pipeline.py
.omx/static-audit-20260713/disasm-bb5a0-bc3ac.txt
.omx/static-audit-20260713/disasm-bea74-bf5fc.txt
.omx/static-audit-20260713/disasm-bf5fc-c0180.txt
.omx/static-audit-20260713/disasm-c0180-c0d84.txt
.omx/static-audit-20260713/unidbg-detector-scratch-remaining-jni-raw.log
native-reimplementation/recovered_primitives.cpp
```
