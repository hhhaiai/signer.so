# Pixel 8 / Android 16 (API 36) signer baseline

This directory preserves the exact APK, certificate, observed device profile,
signer input, and signer output used for byte-for-byte host verification.

- Device serial: `37101FDJH0077P`
- Package: `local.qbdi.adjustreference`
- APK SHA-256: `394c2d0c235125925f85b196ffe4fd1a15fff35eb8b889a9e1e7cee3096e20d1`
- Certificate DER SHA-256: `dd7bb97094bf222be86d2e4003c96454caab1f18fb7033e2b8a65642678c55c4`
- Raw signature SHA-256: `f2c90ec1284661b35b8d21579a1e8907a9aa38c1db0a74d4ad84d1f555bd46d9`

Run the strict host comparison with:

```bash
./generate-signer.sh device-reference/references/pixel8-api36/signer-job.json
```
