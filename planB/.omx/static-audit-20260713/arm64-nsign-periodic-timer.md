# ARM64 nSign periodic timer installer

## Range and ABI

- ARM64 FDE: `0xd4908..0xd4e0c`
- x86_64 equivalent: `0xc1c33..0xc2115`
- signature: no consumed input arguments and no meaningful return value
- nSign call-site: `0xccdc0`

## Recovered order

1. `0xd4c74` invokes callback `0xd4e0c` synchronously on every call.
2. `0xd4c4c` reads process-global installed byte `0x146b20`.
3. When already installed, return without another `timer_create`.
4. Otherwise build `sigevent` with `SIGEV_THREAD` (`2`), callback
   `0xd4e0c`, zero `sigval`, and null thread attributes.
5. `timer_create(CLOCK_MONOTONIC=1, ..., &globalTimer@0x146b28)`.
6. On create success, arm the timer with both `it_interval` and `it_value`
   equal to `{1 second, 0 nanoseconds}` and flags `0`.
7. Set installed byte to `1` only after `timer_settime` succeeds.

Both failures are silently ignored.  A timer created before a
`timer_settime` failure is not deleted in this function.

## Owned C++

- `modelRecoveredPeriodicTimerInstall()`
- `runRecoveredPeriodicTimerInstall()`

The runtime form injects timer operations and therefore does not execute an
OS timer during static-analysis regression.
