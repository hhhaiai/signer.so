# Native reimplementation workbench

This directory contains independently compiled C++ recovered from the ARM64
`libsigner.so`. It does not load the AAR, Unidbg, JNI, or the original SO.

Run:

```bash
cd /Users/sanbo/Desktop/api/qbdi
./native-reimplementation/build-and-test.sh
```

Currently recovered and executable:

- the standard AES-256 key schedule and single-block encryption primitive;
- the fixed signer AES key used by the captured 3.67.0 path;
- the Pixel 8 first-body-block AES test vector;
- the 16-halfword basis and transform at `libsigner.so+0x13531c`;
- observed correction vectors `0x2b`, `0x36`, `0x25`, and `0x05`.

This is a verified native-source slice, not yet a complete replacement for
`libsigner.so`. The Java signer still uses Unidbg and the original ARM64 SO.
The replacement becomes complete only when the entire 176-byte result is
produced by this source and matches both the original SO and the frozen Pixel
reference for the same `DeviceProfile` and request.
