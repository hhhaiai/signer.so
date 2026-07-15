#!/usr/bin/env python3
"""Cross-ABI static proof for the Raspberry manufacturer probe at 0x2c618."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
ARM64_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM_EH = (AUDIT / "arm64-eh-frame.txt").read_text(errors="replace").lower()
X64_EH = (AUDIT / "x86_64-eh-frame.txt").read_text(errors="replace").lower()
ARM = (AUDIT / "disasm-2c618-2cc9c.txt").read_text(errors="replace").lower()
X64 = (AUDIT / "disasm-x86-2cd12-2d13c.txt").read_text(
    errors="replace"
).lower()
CALLER = (AUDIT / "disasm-f328-fce0.txt").read_text(errors="replace").lower()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
).lower()
COVERAGE = (ROOT / "native-reimplementation/SO_FUNCTION_COVERAGE.md").read_text(
    errors="replace"
).lower()


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.S) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def main() -> None:
    require(ARM_EH, r"pc=0002c618\.\.\.0002cc9c", "ARM64 FDE")
    require(X64_EH, r"pc=0002cd12\.\.\.0002d13c", "x86_64 FDE")
    print("ARM64/x86_64 FDE ranges: PASS")

    plains = (
        b"ro.product.manufacturer\0",
        b"raspberry\0",
        b"ro.product.vendor.manufacturer\0",
    )
    arm_data = ARM64_SO.read_bytes()
    x64_data = X86_64_SO.read_bytes()
    arm_specs = ((0x13B690, 0xA0), (0x13B898, 0x40), (0x13B8B0, 0xF2))
    x64_specs = ((0x134060, 0xB5), (0x134268, 0xB2), (0x134280, 0xF4))
    for plain, (offset, key) in zip(plains, arm_specs):
        cipher = arm_data[offset : offset + len(plain)]
        if bytes(value ^ key for value in cipher) != plain:
            raise AssertionError(f"ARM64 XOR plaintext mismatch at 0x{offset:x}")
    for plain, (offset, key) in zip(plains, x64_specs):
        cipher = x64_data[offset : offset + len(plain)]
        if bytes(value ^ key for value in cipher) != plain:
            raise AssertionError(f"x86_64 XOR plaintext mismatch at 0x{offset:x}")
    print("cross-ABI property names and raspberry marker: PASS")

    require(
        ARM,
        r"2c8dc:.*add\s+x11,\s*x11,\s*#0x898.*"
        r"2c8f0:.*eor\s+w8,\s*w8,\s*#0x40.*"
        r"2c920:.*strb\s+w8,\s*\[x10,\s*#0x720\]",
        "ARM64 raspberry XOR-once initialization",
    )
    require(
        ARM,
        r"2ca38:.*ldrb\s+w8,\s*\[x23,\s*#0x18\].*"
        r"2ca3c:.*mov\s+w15,\s*#0xf2.*"
        r"2cac4:.*strb\s+w10,\s*\[x8,\s*#0x721\]",
        "ARM64 vendor property XOR-once initialization",
    )
    require(
        ARM,
        r"2cb94:.*adrp\s+x8,\s*0x143000.*"
        r"2cb98:.*add\s+x8,\s*x8,\s*#0x690.*"
        r"2cb9c:.*movi\s+v2\.16b,\s*#0xa0.*"
        r"2cbd0:.*strb\s+w8,\s*\[x10,\s*#0x702\]",
        "ARM64 manufacturer property XOR-once initialization",
    )
    require(
        X64,
        r"2cf06:.*xorq.*# 0x13c268.*"
        r"2cf1b:.*movb\s+\$0x1.*# 0x13ede9.*"
        r"2cf88:.*movaps.*# 0x13c280.*"
        r"2cfd2:.*movb\s+\$0x1.*# 0x13edeb.*"
        r"2d03c:.*movaps.*# 0x13c060.*"
        r"2d05e:.*movb\s+\$0x1.*# 0x13edad",
        "x86_64 three XOR-once initializers",
    )
    print("cross-ABI XOR-once initialization protocol: PASS")

    require(
        ARM,
        r"2cc0c:.*adrp\s+x10,\s*0x143000.*"
        r"2cc10:.*add\s+x11,\s*x10,\s*#0x690.*"
        r"2cc14:.*mov\s+w8,\s*#0x3.*"
        r"2cc18:.*mov\s+w9,\s*#0x1.*"
        r"2cc20:.*add\s+x10,\s*x10,\s*#0x898.*"
        r"2cc28:.*mov\s+w1,\s*#0x2.*"
        r"2cc30:.*str\s+w8,\s*\[x19,\s*#0xa8\].*"
        r"2cc34:.*stp\s+x11,\s*x10,\s*\[x19\].*"
        r"2cc38:.*str\s+x9,\s*\[x19,\s*#0xf8\].*"
        r"2cc3c:.*stp\s+x23,\s*x10,\s*\[x20,\s*#-0x100\].*"
        r"2cc40:.*stur\s+w8,\s*\[x20,\s*#-0x58\].*"
        r"2cc44:.*stur\s+x9,\s*\[x20,\s*#-0x8\].*"
        r"2cc48:.*sturh\s+wzr.*"
        r"2cc4c:.*bl\s+0x24444.*"
        r"2cc50:.*ldurh\s+w8.*"
        r"2cc60:.*cset\s+w0,\s*ne",
        "ARM64 two-record layout, batch call and boolean return",
    )
    require(
        X64,
        r"2d0a7:.*# 0x13c060.*"
        r"2d0b6:.*# 0x13c268.*"
        r"2d0c8:.*movl\s+%ecx,\s*-0x158\(%r12\).*"
        r"2d0d3:.*movq\s+%rdx,\s*-0x108\(%r12\).*"
        r"2d0db:.*# 0x13c280.*"
        r"2d0ea:.*movq\s+%rax,\s*-0xf8\(%r12\).*"
        r"2d0f2:.*movl\s+%ecx,\s*-0x58\(%r12\).*"
        r"2d0f7:.*movq\s+%rdx,\s*-0x8\(%r12\).*"
        r"2d104:.*popq\s+%rsi.*"
        r"2d10b:.*callq\s+0x2702f.*"
        r"2d110:.*cmpw\s+\$0x0.*"
        r"2d116:.*setne\s+%al",
        "x86_64 two-record layout, batch call and boolean return",
    )
    print("cross-ABI record layout and count-to-bool return: PASS")

    require(
        CALLER,
        r"f850:.*bl\s+0x2c618.*"
        r"f854:.*tst\s+w0,\s*#0x1.*"
        r"f984:.*mov\s+w1,\s*#0x28",
        "sole caller and correction 0x28",
    )
    print("environment dispatcher correction 0x28 edge: PASS")

    for symbol in (
        "krecoveredmanufacturerproperty2c618",
        "krecoveredvendormanufacturerproperty2c618",
        "krecoveredraspberrymarker2c618",
        "runrecoveredraspberrymanufacturerprobe2c618",
        "recoveredraspberrymanufacturerprobe2c618regression",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ symbol {symbol}")
    require(
        CPP,
        r"std::array<recovereddescriptorbatchrecord24444,\s*2>\s+records.*"
        r"records\[0\]\.descriptorkinds\[0\]\s*=\s*3.*"
        r"records\[0\]\.descriptorcount\s*=\s*1.*"
        r"records\[1\]\.descriptorkinds\[0\]\s*=\s*3.*"
        r"records\[1\]\.descriptorcount\s*=\s*1.*"
        r"std::uint16_t\s+matchcount\s*=\s*0.*"
        r"runrecovereddescriptorbatch24444\(records\.data\(\),\s*records\.size\(\).*"
        r"return\s+matchcount\s*!=\s*0",
        "C++ two-record batch and boolean return",
    )
    require(
        CPP,
        r"if\s*\(!recoveredraspberrymanufacturerprobe2c618regression\(\)\)",
        "top-level regression guard",
    )
    require(
        COVERAGE,
        r"`0x2c618\.\.0x2cc9c`.*raspberry manufacturer system-property probe.*"
        r"\*\*recovered\*\*",
        "recovered coverage row",
    )
    print("C++ implementation, regression and coverage: PASS")


if __name__ == "__main__":
    main()
