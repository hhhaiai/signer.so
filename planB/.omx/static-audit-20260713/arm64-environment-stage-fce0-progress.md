# ARM64 `0xfce0..0x12a30` environment stage-1 initializer progress

## Confirmed reachable behavior

The FDE is a flattened, process-global emulator/automation detector
initializer. A full-range local Unidbg trace on the frozen Pixel job executed
55,295 instructions and 2,855 unique PCs while preserving the exact 176-byte
signature. Intersecting executed PCs with direct-call sites proves:

- all 24 calls to acquire-byte CAS helper `0x139800` are reached;
- decoy correction-array call `0x11600 -> 0x1354bc` is not reached on the
  frozen clean profile;
- the post-initialization chain is `memset(0x90) -> 0x7ba5c -> 0x7bbb0(24)
  -> 0x868b4(24) -> 0x13044`;
- return value at `0x129dc..0x129f0` is exactly `*status == 0`.

The trace instrumentation was temporary. The Java runner source was restored
byte-for-byte after capture; the durable evidence is stored in:

```text
fce0-full-trace-original.stdout
fce0-full-trace-original.stderr
fce0-executed-pcs.txt
fce0-global-byte-diff.txt
```

## Recovered plaintext tables

Entry/exit snapshots of module data and BSS found 634 changed bytes. BSS
`+0x182..+0x19a` becomes 24 initialized bytes. The changed data reconstructs
two plaintext marker groups.

The 24-pointer table passed to both `0x7bbb0` and `0x868b4` is:

```text
Emulator, AMIDuOS, AndroidStudio, Android Studio, ARChon, Bluestacks,
Droid4X, Genymotion, KoPlaMEmu, Remix, Xamarin, YouWave, LeapDroid,
KoPlayer, Robotium, Bot-Bot, SeeTest, MonkeyRunner, Ranorex, Appium,
Automator, google_sdk, Android SDK built for x86, redfinger
```

The remaining 23 decoded build/product markers are:

```text
android, android-x86, android sdk built for x86,
android sdk built for x86_64, generic_x86, generic_x86_64, google_sdk,
android sdk built for arm64, android sdk built for armv7, android_x86,
sdk_x86_64, sdk_x86, vbox86p, sdk_google, sdk_google_phone_x86_64,
sdk_google_phone_arm64, sdk_gphone64_arm64, sdk_google_phone_arm,
google/sdk_gphone_, google/sdk_gphone64_, itools, apple, iphone
```

These are now immutable plaintext arrays in `recovered_primitives.cpp`, which
is the source-level equivalent of publishing XOR-decoded writable globals
under one-time locks.

## Final recovered control flow

`0x1354bc..0x135640`, the correction-array callee used by the detector's
positive-score path, is independently closed: it handles null/count no-op and
writes each uint16 correction in ascending order; its caller owns flag bit
zero.

The `0x7ba5c` fanout wrapper, all fourteen ARM64 detector bodies, the fixed
matcher `0x7bbb0`, the dynamic-slot matcher `0x868b4`, and the previously opaque
`0x352d4 -> 0x36bfc` build-identity path are independently closed.  Removing
the flattened state dispatcher leaves this source-level order:

1. Publish the 24 decoded marker pointers and clear a 0x90-byte correction
   array, a float score and a uint64 correction count.
2. Run the fourteen detector stages in the exact `0x7ba5c` order and store its
   unconditional zero return through the status pointer.
3. Run `0x7bbb0` over scratch offsets `00/08/10/18/20/30/38/50`; a hit applies
   `score + (1-score)*0.8` and appends correction `0x19`.
4. Run `0x868b4` over the 16-byte slots at scratch `+0x70`, count `+0x870`; a
   hit applies the same 0.8 contribution and appends correction `0x0c`.
5. If the final score is at least 0.8, call `0x1354bc` to commit corrections in
   array order and then set context flag bit zero.  Scores below 0.8 and NaN
   skip this commit.
6. Call nested mask stage `0x13044` and return `*status == 0`.

`runRecoveredEnvironmentStageFce0` is the direct C++ implementation.  Its
regression covers the clean path, a sub-threshold 0x0b detector, fixed marker
0x19, dynamic marker 0x0c, a strong fanout correction and the recovered
0x352d4 correction-0x13 route.  The FDE can therefore be inventoried as
recovered rather than partial.

Repeatable artifact check:

```bash
python3 .omx/static-audit-20260713/analyze_environment_stage_fce0.py
```
