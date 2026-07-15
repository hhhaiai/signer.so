# ARM64 Android system-property compatibility path

## `0xd43e8..0xd466c`: property-area path formatter

The once-decoded bytes at VMA `0x145880` use XOR key `0x26` and produce:

```text
/dev/__properties__/%s\0
```

`0xd4620/0xd4630` call `vsnprintf(output, 199, format, args)`.

## `0xd4244..0xd43e8`: guarded property reader

Recovered order:

1. Resolve a property-area name from metadata through `0xd313c`.
2. A null area name falls back directly to
   `__system_property_get(property_name, output)`.
3. Otherwise zero a 200-byte stack buffer and format
   `/dev/__properties__/<area>` through `0xd43e8`.
4. Call `access(path, R_OK)`.
5. A readable area uses the direct system-property getter. An unreadable area
   clears `output[0]` and returns zero without reading the property.

## `0xd4678..0xd4900`: Android API dispatcher and metadata cache

- Process-global API is read at `0xd46d0`; the threshold is strict `> 27` at
  `0xd46f4..0xd46fc`.
- API 27 and lower use `__system_property_get` directly.
- API 28+ with a null metadata cache calls initializer `0xd3ff0`, publishes
  its returned pointer unconditionally at `0xd4894`, then:
  - non-null pointer and status zero: use guarded `0xd4244` immediately;
  - null pointer or nonzero status: use the direct getter for that call.
- API 28+ with an already non-null cache uses guarded `0xd4244` without
  initializing again. Therefore a non-null object returned together with a
  failure status is direct-fallback on the first call but guarded on later
  calls; the C++ regression preserves this subtle native state transition.

Owned C++:

- `runRecoveredPropertyAreaPathFormatterD43e8`
- `runRecoveredGuardedSystemPropertyGetD4244`
- `runRecoveredSystemPropertyCompatibilityD4678`
- `recoveredSystemPropertyCompatibilityD4244D4678Regression`
