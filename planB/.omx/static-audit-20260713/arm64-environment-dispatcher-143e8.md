# ARM64 environment dispatcher `0x143e8..0x14e10`

Static instruction interpretation proves this fixed, non-short-circuiting
probe order:

```text
status = 0
if d78b8(status, "/proc/self/maps"): correction 0x22
if status != 0: correction 0x35

status = 0
if db410(status, "/proc/self/fd"): correction 0x23
if status != 0: correction 0x36

if 13063c(): correction 0x25

status = 0
if 1309cc(status): correction 0x2d
if status != 0: correction 0x3a
fridaServerStatus = status

status = 0
if 1311f0(status): correction 0x2e
if fridaServerStatus == 0 and status != 0: correction 0x3a

context.flags |= 0x0460603c00000000
```

The saved `fridaServerStatus` gate matters: when both `0x1309cc` and
`0x1311f0` report nonzero status, the native dispatcher emits only the first
`0x3a`. When only the second status is nonzero, it emits the second helper's
`0x3a`. Result corrections precede status corrections, all later probes still
run, and the final mask is unconditional.

The C++ implementation is callback-driven so the dispatcher is complete while
`0xdb410` and `0x1311f0` continue to be recovered as separate FDEs. `0xd78b8`
is now independently recovered as the case-sensitive `frida-agent` maps
scanner. The dispatcher regression validates the shared status slot, exact
path strings, call order, combined correction order, and final flags.
