# ARM64 loopback Frida-server probe `0x1309cc..0x1311f0`

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
    sendto(fd, "AUTH
", 6, 0, null, 0)
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
