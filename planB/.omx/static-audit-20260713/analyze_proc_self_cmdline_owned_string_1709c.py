#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
import struct
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
ARM_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM_FULL = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace")
X86_FULL = (AUDIT / "x86_64-full-objdump.txt").read_text(errors="replace")
ARM_FRAMES = (AUDIT / "arm64-eh-frame.txt").read_text(errors="replace")
X86_FRAMES = (AUDIT / "x86_64-eh-frame.txt").read_text(errors="replace")
CPP = ROOT / "native-reimplementation/recovered_primitives.cpp"
GENERATOR = AUDIT / "generate_arm64_function_inventory.py"
INVENTORY = AUDIT / "arm64-function-inventory.csv"


def require(condition: bool, description: str) -> None:
    if not condition:
        raise SystemExit(f"missing proof: {description}")


def require_pattern(text: str, pattern: str, description: str) -> None:
    require(re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None,
            description)


def objdump(path: Path, start: int, end: int) -> str:
    return subprocess.run(
        [
            "/usr/bin/objdump", "-d",
            f"--start-address=0x{start:x}",
            f"--stop-address=0x{end:x}",
            str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def body(disassembly: str, start: int, end: int) -> str:
    lines: list[str] = []
    for line in disassembly.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match is not None and start <= int(match.group(1), 16) < end:
            lines.append(line)
    require(bool(lines), f"disassembly {start:#x}..{end:#x}")
    return "\n".join(lines)


def read_virtual(path: Path, address: int, size: int) -> bytes:
    data = path.read_bytes()
    require(data[:6] == b"\x7fELF\x02\x01", f"ELF64 little-endian {path}")
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize = struct.unpack_from("<H", data, 0x36)[0]
    phnum = struct.unpack_from("<H", data, 0x38)[0]
    for index in range(phnum):
        values = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phentsize)
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = values
        if (p_type == 1 and p_vaddr <= address
                and address + size <= p_vaddr + p_filesz):
            start = p_offset + address - p_vaddr
            return data[start:start + size]
    raise SystemExit(f"unmapped VMA {path}:{address:#x}+{size:#x}")


def decoded(path: Path, address: int, size: int, key: int) -> bytes:
    return bytes(value ^ key for value in read_virtual(path, address, size))


def main() -> None:
    arm = body(objdump(ARM_SO, 0x1709C, 0x179F8), 0x1709C, 0x179F8)
    x86 = body(objdump(X86_SO, 0x18909, 0x18FE3), 0x18909, 0x18FE3)
    arm_caller = body(objdump(ARM_SO, 0xCDE4, 0xD184), 0xCDE4, 0xD184)
    x86_caller = body(objdump(X86_SO, 0x111BC, 0x11519),
                      0x111BC, 0x11519)

    require("pc=0001709c...000179f8" in ARM_FRAMES, "ARM64 target FDE")
    require("pc=00018909...00018fe3" in X86_FRAMES, "x86_64 target FDE")
    require("pc=0000cde4...0000d184" in ARM_FRAMES, "ARM64 caller FDE")
    require("pc=000111bc...00011519" in X86_FRAMES, "x86_64 caller FDE")
    require(len(re.findall(r"\bbl\s+0x1709c\b", ARM_FULL)) == 1,
            "one ARM64 direct caller")
    require(len(re.findall(r"\bcallq?\s+0x18909\b", X86_FULL)) == 1,
            "one x86_64 direct caller")
    print("cross-ABI target/caller FDEs and unique caller: PASS")

    require(decoded(ARM_SO, 0x1430D0, 19, 0xB7)
            == b"/proc/self/cmdline\0", "ARM64 decoded cmdline path")
    require(decoded(X86_SO, 0x13BAA0, 19, 0xC5)
            == b"/proc/self/cmdline\0", "x86_64 decoded cmdline path")
    require_pattern(arm, r"171e8:.*0x143000.*171ec:.*#0xd0",
                    "ARM64 encoded-path pointer")
    require(len(re.findall(r"\bbl\s+0x139800\b", arm)) == 2,
            "ARM64 two path-lock acquisitions")
    require(len(re.findall(r"stlrb\s+wzr", arm)) == 2,
            "ARM64 two release stores")
    require(len(re.findall(r"#0xb7", arm)) >= 2,
            "ARM64 XOR-once key")
    require(len(re.findall(r"cmpxchgb.*13ed28", x86)) == 2,
            "x86 two path-lock acquisitions")
    require(len(re.findall(r"movb\s+\$0x0,.*13ed28", x86)) == 2,
            "x86 two release stores")
    require(len(re.findall(r"13ed29", x86)) >= 4,
            "x86 initialized-byte checks/publication")
    print("cross-ABI XOR-once cmdline path and two acquire/release cycles: PASS")

    for pattern, description in [
        (r"17624:.*x0, x21.*17628:.*w1, #0x4.*1762c:.*access@plt",
         "ARM access(path,R_OK)"),
        (r"17550:.*w0, #0x38.*17554:.*w1, #-0x64.*"
         r"17558:.*x2, x21.*1755c:.*w3, wzr.*17560:.*w4, wzr.*"
         r"17568:.*syscall@plt", "ARM openat AT_FDCWD/O_RDONLY"),
        (r"175d8:.*cmn\s+w0, #0x1", "ARM open result equals -1 gate"),
        (r"17754:.*w0, #0x3f.*17758:.*x2.*1775c:.*w3, #0xfff.*"
         r"17760:.*w1, w21.*17764:.*syscall@plt", "ARM read max 4095"),
        (r"17768:.*x19, x0.*1776c:.*w0, #0x39.*17770:.*w1, w21.*"
         r"17788:.*syscall@plt", "ARM unconditional close after read"),
        (r"177ac:.*x19.*177b0:.*cmp\s+x19, #0x0",
         "ARM read checks only equality with zero"),
        (r"17414:.*x8.*17418:.*x0, x8, #0x1.*1741c:.*malloc@plt",
         "ARM wrapping readLength+1 allocation"),
        (r"173ec:.*ldp\s+x10, x8.*17404:.*strb\s+wzr, \[x8, x10\]",
         "ARM heap terminator before copy"),
        (r"1782c:.*ldp\s+x9, x10.*17830:.*ldrb.*1783c:.*strb.*"
         r"17840:.*sub\s+x11, x9, #0x1", "ARM byte copy loop"),
        (r"17528:.*1752c:.*x8.*17530:.*x10.*17540:.*str\s+x10, \[x8\]",
         "ARM output publication after copy"),
        (r"178ec:.*x8.*178f4:.*#0x2.*17900:.*str\s+xzr, \[x8\].*"
         r"1790c:.*str\s+w10", "ARM malloc failure output clear/status 2"),
        (r"1796c:.*17974:.*#0x8.*17984:.*str\s+w10",
         "ARM access-or-empty status 8"),
        (r"179a0:.*179a8:.*#0xc.*179b8:.*str\s+w10",
         "ARM open status 12"),
    ]:
        require_pattern(arm, pattern, description)

    for pattern, description in [
        (r"18d4b:.*0x13baa0.*18d52:.*\$0x4.*18d55:.*access@plt",
         "x86 access(path,R_OK)"),
        (r"18cb9:.*\$0x101.*18cbe:.*\$-0x64.*18cc1:.*0x13baa0.*"
         r"18cc8:.*%ecx.*18cca:.*%r8d.*18ccf:.*syscall@plt",
         "x86 openat AT_FDCWD/O_RDONLY"),
        (r"18d14:.*cmpl\s+\$-0x1, %eax", "x86 open result equals -1 gate"),
        (r"18e10:.*\$0xfff.*18e15:.*%edi.*18e1b:.*%esi.*"
         r"18e1e:.*%rdx.*18e24:.*syscall@plt", "x86 read max 4095"),
        (r"18e32:.*%rax, %r13.*18e35:.*\$0x3.*18e38:.*%esi.*"
         r"18e3d:.*syscall@plt", "x86 unconditional close after read"),
        (r"18e42:.*%r13.*18e46:.*testq\s+%r13, %r13",
         "x86 read checks only equality with zero"),
        (r"18ba5:.*18ba9:.*0x1\(%rax\).*18bad:.*malloc@plt",
         "x86 wrapping readLength+1 allocation"),
        (r"18b7a:.*18b82:.*movb\s+\$0x0, \(%rax,%rcx\)",
         "x86 heap terminator before copy"),
        (r"18eb5:.*movq.*18ec1:.*movb.*18ed2:.*movb.*18edb:.*decq",
         "x86 byte copy loop"),
        (r"18c98:.*18c9c:.*18ca0:.*movq\s+%rcx, \(%rax\)",
         "x86 output publication after copy"),
        (r"18f10:.*18f14:.*andq\s+\$0x0, \(%rax\).*"
         r"18f18:.*18f1c:.*\$0x2", "x86 malloc failure output clear/status 2"),
        (r"18f6a:.*18f6e:.*\$0x8", "x86 access-or-empty status 8"),
        (r"18fa7:.*18fab:.*\$0xc", "x86 open status 12"),
    ]:
        require_pattern(x86, pattern, description)
    print("cross-ABI access/open/read/close/allocation/copy state machine: PASS")

    require_pattern(
        arm_caller,
        r"ce30:.*stur\s+wzr.*ce34:.*stur\s+xzr.*ce44:.*x0.*"
        r"ce48:.*x1.*ce4c:.*0x1709c",
        "ARM caller zero-init and status/output forwarding",
    )
    require_pattern(
        x86_caller,
        r"111fe:.*\(%r12\).*11203:.*%r14.*11208:.*\(%r14\).*"
        r"11219:.*%r12, %rdi.*1121c:.*%r14, %rsi.*1121f:.*0x18909",
        "x86 caller zero-init and status/output forwarding",
    )
    print("cross-ABI caller zero-init, forwarding and ownership handoff: PASS")
    print("read<0 is not rejected; read=-1 wraps allocation size to zero: PASS")

    cpp = CPP.read_text(errors="replace")
    generator = GENERATOR.read_text(errors="replace")
    require_pattern(
        cpp,
        r'kRecoveredProcSelfCmdlinePath1709c\[\].*?"/proc/self/cmdline".*?'
        r'struct RecoveredProcSelfCmdlineOperations1709c.*?void\* context;.*?'
        r'accessPath.*?openAt.*?readFile.*?closeFile.*?allocate.*?'
        r'storeTerminator.*?copyBytes',
        "caller-supplied C++ operations and fixed OS path",
    )
    require_pattern(
        cpp,
        r'runRecoveredProcSelfCmdlineOwnedString1709c\(.*?'
        r'accessPath\(operations\.context.*?R_OK\).*?\*status = 8;.*?'
        r'openAt\(operations\.context,\s*-100,.*?, 0, 0\).*?'
        r'fileDescriptorBits.*?static_cast<std::uint64_t>\(openResult\).*?'
        r'fileDescriptorBits == 0xffffffffU.*?\*status = 12;.*?'
        r'std::memcpy\(&fileDescriptor, &fileDescriptorBits.*?'
        r'readFile\(.*?0x0fff\).*?closeFile\(.*?fileDescriptor\).*?'
        r'if \(readResult == 0\).*?\*status = 8;.*?'
        r'static_cast<std::uint64_t>\(readResult\).*?'
        r'length \+ std::uint64_t\{1\}.*?allocation == nullptr.*?'
        r'\*output = 0;.*?\*status = 2;.*?storeTerminator.*?copyBytes.*?'
        r'\*output = static_cast<std::uint64_t>',
        "C++ status, ordering, wrapping allocation and late publication",
    )
    require("recoveredProcSelfCmdlineOwnedString1709cRegression" in cpp,
            "direct C++ regression")
    require("proc-self cmdline owned-string reader 0x1709c regression failed"
            in cpp, "main regression guard")
    require_pattern(
        cpp,
        r'readResult = -1;.*?allocationFails = true.*?'
        r'observedAllocationSize != 0.*?readResult = -1;.*?'
        r'zeroAllocationReturnsNonNull = true.*?'
        r'observedTerminatorOffset == ~std::uint64_t\{0\}.*?'
        r'observedCopyLength == ~std::uint64_t\{0\}.*?'
        r'unsafeTerminatorObserved.*?unsafeCopyObserved',
        "safe regression proof of original negative-read hazard",
    )
    require_pattern(
        cpp,
        r'readResult = 0x0fff;.*?readBytes\.assign\(0x0fff, 0x5a\).*?'
        r'observedAllocationSize == 0x1000.*?'
        r'observedTerminatorOffset == 0x0fff.*?'
        r'observedCopyLength == 0x0fff',
        "direct 4095-byte boundary regression",
    )
    require_pattern(
        generator,
        r'0x01709C: \("/proc/self/cmdline owned-string producer", '
        r'"recovered"',
        "generator recovered entry",
    )
    with INVENTORY.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    matches = [row for row in rows if row["start"].lower() == "0x1709c"]
    require(len(matches) == 1, "one generated 0x1709c inventory row")
    require(matches[0]["end"].lower() == "0x179f8",
            "generated 0x1709c end")
    require(matches[0]["status"] == "recovered",
            "generated 0x1709c recovered status")
    require(matches[0]["reachable"] == "yes",
            "generated 0x1709c JNI reachability")
    print("C++ implementation, regression and generated recovered coverage: PASS")


if __name__ == "__main__":
    main()
