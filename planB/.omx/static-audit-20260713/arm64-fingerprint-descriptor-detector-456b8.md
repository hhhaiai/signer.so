# ARM64 `0x456b8..0x47778` fingerprint descriptor detector

## Inputs and gate

- `x0` is saved at `sp+0x20`; `0x46f2c..0x46f3c` loads `scratch+0x00`.
- `0x46f50` combines the non-null value check with the correction-array check.
- Null input, null correction array, or null `scratch+0x00` produces no mutation.

## Descriptor call

`0x46c28..0x46cc8` invokes `0x42eb0` with:

- value: `scratch+0x00`;
- descriptor pointer array: `sp+0x88`;
- kind array: `sp+0x50`;
- count: `11`.

The decoded descriptors, in native order, are:

```text
sdk_x86_64
sdk
google_sdk
sdk_x86
vbox86p
sdk_google
sdk_google_phone_x86_64
sdk_google_phone_arm64
sdk_gphone64_arm64
vbox
sdk_gphone_
```

Their kind tags are exactly:

```text
0, 0, 0, 0, 0, 3, 0, 0, 3, 3, 1
```

The first four zeros come from `stp xzr,xzr`; the middle four values come
from the 16-byte constant at file offset `0x2f80`; `movi v14.2s,#3` supplies
the next two threes; the final one is stored at `sp+0x78`.

## `0x23730` routes used here

- kind `0` -> inline full-string ASCII-case-insensitive equality;
- kind `1` -> `0x12ad00`: ASCII-case-insensitive prefix;
- kind `3` -> `0x12ba10`: ASCII-case-insensitive overlapping substring.

Only ASCII `A..Z` is folded. Kind zero rejects either-side extra bytes. Kind
one requires the marker at offset zero but permits following bytes. Kind
three restarts at the next candidate byte, preserving overlapping candidates;
its native outer loop makes `("", "")` false but `("x", "")` true.

## Mutation

Any descriptor match appends correction `0x15` and raises the score to `1.0f`.
The native observable store order is:

```text
0x46c04 score
0x46c10 correctionCount
0x46c1c correction[index] = 0x15
```

The direct C++ implementation preserves this ordering in
`runRecoveredFingerprintDescriptorDetector456b8`.

## Machine-checkable evidence

Run:

```bash
python3 .omx/static-audit-20260713/analyze_fingerprint_descriptor_detector_456b8.py
```

The analyzer checks the call/gate/store instructions, all XOR-decoded marker
bytes, the kind-array construction, the three dispatcher routes, helper
semantics anchors, C++ store order, and targeted regression presence.
