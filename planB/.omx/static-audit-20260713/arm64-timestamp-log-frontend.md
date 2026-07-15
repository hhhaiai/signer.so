# Timestamp log front end

## Ranges

- ARM64: `0x12ec1c..0x12f298`
- x86_64: `0x1296f4..0x129ad0`

## Signature

```cpp
void timestampLog(const char* label, double epochMilliseconds);
```

ARM64 receives the label in `x0` and milliseconds in `d0`; x86_64 uses
`rdi`/`xmm0`.

## Recovered transformation

```text
seconds = trunc(milliseconds / 1000.0)
millisecondComponent = trunc(fmod(milliseconds, 1000.0))
local = localtime(&seconds)
date = strftime(20, "%Y-%m-%dT%H:%M:%S", local)
zone = strftime(6, "%z", local)
line = "%s: %s.%03dZ%s" % (label, date, millisecondComponent, zone)
forward line through 0x12fa24
```

`localtime` is intentional: the line contains a literal `Z` followed by the
numeric local offset, for example `...123Z+0800`. This odd format must not be
silently normalized to UTC in a compatibility implementation.

The nSign labels decode to:

```text
Signing all the parameters begin
Signing all the parameters end  
```

The second label contains two spaces after `end` before its NUL terminator.
The first outer realtime sample is used for the begin line and the second for
the end line.

## C++

- `modelRecoveredTimestampLog()`
- `runRecoveredTimestampLog()`

The downstream `0x12fa24..0x13063c` Android-log routing remains a separate
recovery unit; this front end is closed at its exact callee boundary.
