# ARM64 proc-maps Frida scanner `0xd78b8..0xdb410`

## Status

Recovered by complete flattened-FDE interpretation with stubbed file/libc
operations. The interpreter does not load or execute `libsigner.so`.

## Exact behavior

1. Preserve the incoming status unless an open precondition fails.
2. Call `access(path, R_OK=4)`; failure writes status `8` and returns false.
3. Call `fopen(path, "r")`; null writes status `8` and returns false.
4. Repeatedly call the local getline-compatible helper `0xd6ed8`.
5. Search each NUL-terminated line for the case-sensitive substring
   `frida-agent`; a match returns true and stops before another read.
6. Free a non-null owned line buffer, then call `fclose`; EOF and close failure
   do not change status.

The one-time decoded literals are exactly `r` (XOR `0x85`) and
`frida-agent` (XOR `0x45`). The direct C++ execution form is
`runRecoveredProcMapsFridaScannerD78b8()`, with callback regression coverage
in `recoveredProcMapsFridaScannerD78b8Regression()`.
