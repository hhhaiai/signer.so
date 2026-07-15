#!/usr/bin/env python3
"""Verify the complete static recovery of ARM64 0x1309cc..0x1311f0."""

from __future__ import annotations

import pathlib
import re
import struct


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
DISASM = (HERE / "disasm-1309cc-1311f0.txt").read_text()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


def require(pattern: str, label: str) -> None:
    if re.search(pattern, DISASM, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def virtual_bytes(address: int, size: int) -> bytes:
    data = SO.read_bytes()
    section_offset = struct.unpack_from("<Q", data, 0x28)[0]
    section_entry_size = struct.unpack_from("<H", data, 0x3A)[0]
    section_count = struct.unpack_from("<H", data, 0x3C)[0]
    for index in range(section_count):
        section = struct.unpack_from(
            "<IIQQQQIIQQ", data,
            section_offset + index * section_entry_size,
        )
        virtual_address, file_offset, section_size = section[3:6]
        if virtual_address <= address < virtual_address + section_size:
            offset = file_offset + address - virtual_address
            return data[offset:offset + size]
    raise AssertionError(f"unmapped address {address:#x}")


assert bytes(value ^ 0x63 for value in virtual_bytes(0x146008, 10)) \
    == b"127.0.0.1\0"
assert bytes(value ^ 0x68 for value in virtual_bytes(0x146014, 7)) \
    == b"AUTH\r\n\0"
assert struct.unpack("<qq", virtual_bytes(0x2FD0, 16)) == (0, 100000)

# Two independent atomic XOR-once decoders guard the loopback address and
# protocol probe. The release stores and initialized bytes are distinct.
require(r"130fa4:.*adr\s+x2, 0x146b98", "address lock")
require(r"130f28:.*adr\s+x11, 0x146008", "address bytes")
require(r"130f6c:.*strb\s+w10, \[x8, #0xba5\]", "address initialized")
require(r"130e78:.*adr\s+x8, 0x146b98", "address unlock")
require(r"130d08:.*adr\s+x2, 0x146b9c", "AUTH lock")
require(r"131020:.*adr\s+x15, 0x146014", "AUTH bytes")
require(r"131094:.*strb\s+w8, \[x10, #0xba6\]", "AUTH initialized")
require(r"130d88:.*adr\s+x8, 0x146b9c", "AUTH unlock")

# sockaddr_in is zeroed, then filled with AF_INET, network-order port 27042,
# and inet_aton("127.0.0.1"). Its return value is ignored.
require(r"130e88:.*mov\s+w8, #0x2", "AF_INET family")
require(r"130e90:.*sturh\s+w8, \[x29, #-0x30\]", "family store")
require(r"130e98:.*mov\s+w8, #0xa269", "network port 27042")
require(r"130ea8:.*sturh\s+w8, \[x29, #-0x2e\]", "port store")
require(r"130e94:.*bl\s+0x13a110 <inet_aton@plt>", "inet_aton")

# socket(AF_INET, SOCK_STREAM, 0); a negative descriptor writes status 6 and
# returns false without close.
require(r"130e9c:.*mov\s+w0, #0x2", "socket domain")
require(r"130ea0:.*mov\s+w1, #0x1", "socket type")
require(r"130ea4:.*mov\s+w2, wzr", "socket protocol")
require(r"130eac:.*bl\s+0x13a120 <socket@plt>", "socket call")
require(r"130ee0:.*cmp\s+w0, #0x0", "negative descriptor gate")
require(r"130f7c:.*mov\s+w10, #0x6", "status 6")
require(r"130f90:.*str\s+w10, \[x8\]", "status store")

# setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, {0,100000}, 16) is followed by
# connect(fd, &sockaddr, 16). setsockopt is intentionally unchecked and only
# exact connect result -1 selects the failure path.
require(r"1310a8:.*mov\s+w1, #0x1", "SOL_SOCKET")
require(r"1310ac:.*mov\s+w2, #0x14", "SO_RCVTIMEO")
require(r"1310b0:.*mov\s+w4, #0x10", "timeout size")
require(r"1310bc:.*bl\s+0x13a130 <setsockopt@plt>", "setsockopt")
require(r"1310cc:.*mov\s+w2, #0x10", "sockaddr size")
require(r"1310dc:.*bl\s+0x13a140 <connect@plt>", "connect")
require(r"1310fc:.*cmn\s+w0, #0x1", "exact connect -1 gate")

# Successful connect sends exactly six AUTH bytes, receives up to 256 bytes,
# and treats only recvfrom == 0 as detection. sendto/recvfrom arguments use no
# peer address because the socket is already connected.
require(r"130d94:.*mov\s+w2, #0x6", "AUTH length")
require(r"130da0:.*mov\s+x4, xzr", "sendto null destination")
require(r"130da8:.*mov\s+w5, wzr", "sendto zero destination length")
require(r"130dac:.*bl\s+0x13a0f0 <sendto@plt>", "sendto")
require(r"130e14:.*mov\s+w2, #0x100", "receive capacity")
require(r"130e20:.*mov\s+x4, xzr", "recvfrom null source")
require(r"130e24:.*mov\s+x5, xzr", "recvfrom null source length")
require(r"130e28:.*bl\s+0x13a100 <recvfrom@plt>", "recvfrom")
require(r"130e2c:.*cmp\s+x0, #0x0", "recv zero compare")
require(r"130e38:.*cset\s+w8, eq", "recv zero verdict")

# Valid descriptors are closed through raw ARM64 close syscall number 57;
# the close result is ignored and the saved verdict is returned as one bit.
require(r"130d3c:.*mov\s+w0, #0x39", "close syscall number 57")
require(r"130d44:.*bl\s+0x139e00 <syscall@plt>", "close syscall")
require(r"1311c0:.*ldur\s+w8, \[x29, #-0x6c\]", "saved verdict")
require(r"1311c4:.*and\s+w0, w8, #0x1", "boolean return")

for symbol in (
    "RecoveredXorOnceStringState1309cc",
    "RecoveredSockaddrIn1309cc",
    "RecoveredFridaServerProbe1309ccOperations",
    "runRecoveredFridaServerProbe1309cc",
    "recoveredFridaServerProbe1309ccRegression",
):
    if symbol not in CPP:
        raise AssertionError(f"missing C++ symbol {symbol}")

(HERE / "arm64-frida-server-probe-1309cc.md").write_text(
    """# ARM64 loopback Frida-server probe `0x1309cc..0x1311f0`

The FDE owns two atomic XOR-once strings and performs this sequence:

```text
address = "127.0.0.1"
sockaddr = {AF_INET, port 27042, inet_aton(address), zero padding}
fd = socket(AF_INET, SOCK_STREAM, 0)
if fd < 0:
    *status = 6
    return false

setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, {0 sec, 100000 usec}, 16)
if connect(fd, &sockaddr, 16) != -1:
    sendto(fd, "AUTH\r\n", 6, 0, null, 0)
    detected = recvfrom(fd, buffer[256], 256, 0, null, null) == 0
else:
    detected = false
syscall(57 /* close */, fd)
return detected
```

The return values of `inet_aton`, `setsockopt`, `sendto`, and close are
ignored. A valid descriptor is always closed after either connect branch.
Only a negative socket descriptor writes status 6 and skips close. The C++
regression verifies socket failure, connect failure, zero-byte receive, and
positive receive event/argument matrices without executing any network I/O.
"""
)

print("arm64 Frida-server probe 0x1309cc evidence: PASS")
