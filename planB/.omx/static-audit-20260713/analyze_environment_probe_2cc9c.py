#!/usr/bin/env python3
import csv
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
ARM64_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM = (AUDIT / "disasm-2cc9c-2e1d4.txt").read_text(errors="replace").lower()
X64 = (AUDIT / "disasm-x86-2d13c-2dba0.txt").read_text(errors="replace").lower()
ARM_EH = (AUDIT / "arm64-eh-frame.txt").read_text(errors="replace").lower()
X64_EH = (AUDIT / "x86_64-eh-frame.txt").read_text(errors="replace").lower()
CALLER = (AUDIT / "disasm-f328-fce0.txt").read_text(errors="replace").lower()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
).lower()


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.DOTALL) is None:
        raise AssertionError(description)


def decode_at(data: bytes, offset: int, key: int, plain: bytes, abi: str) -> None:
    cipher = data[offset : offset + len(plain)]
    actual = bytes(value ^ key for value in cipher)
    if actual != plain:
        raise AssertionError(
            f"{abi} XOR plaintext mismatch at 0x{offset:x}: {actual!r}"
        )


def inventory_row(address: int) -> dict[str, str]:
    path = AUDIT / "arm64-function-inventory.csv"
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            if int(row["start"], 0) == address:
                return row
    raise AssertionError(f"missing inventory row 0x{address:x}")


def main() -> None:
    require(ARM_EH, r"pc=0002cc9c\.\.\.0002e1d4", "ARM64 FDE")
    require(X64_EH, r"pc=0002d13c\.\.\.0002dba0", "x86_64 FDE")
    print("ARM64/x86_64 FDE ranges: PASS")

    plains = (
        b"ro.product.manufacturer\0",
        b"ro.product.vendor.manufacturer\0",
        b"ro.product.model\0",
        b"minical\0",
        b"vcloud\0",
        b"ro.product.vendor.model\0",
        b"ro.build.display.id\0",
        b"Scorpio_rt OS\0",
    )
    arm_specs = (
        (0x13B690, 0xA0),
        (0x13B8B0, 0xF2),
        (0x13B6B0, 0x5A),
        (0x13B8D0, 0x66),
        (0x13B8D8, 0xF1),
        (0x13B8E0, 0x4F),
        (0x13B900, 0x26),
        (0x13B918, 0x9A),
    )
    x64_specs = (
        (0x134060, 0xB5),
        (0x134280, 0xF4),
        (0x134080, 0x99),
        (0x1342A0, 0x0E),
        (0x1342A8, 0x4D),
        (0x1342B0, 0x57),
        (0x1342D0, 0xBA),
        (0x1342E8, 0xAC),
    )
    arm_data = ARM64_SO.read_bytes()
    x64_data = X86_64_SO.read_bytes()
    for plain, (offset, key) in zip(plains, arm_specs):
        decode_at(arm_data, offset, key, plain, "ARM64")
    for plain, (offset, key) in zip(plains, x64_specs):
        decode_at(x64_data, offset, key, plain, "x86_64")
    print("cross-ABI property names and minical/vcloud/Scorpio markers: PASS")

    arm_cas = re.findall(r"\bbl\s+0x139800\b", ARM)
    arm_releases = re.findall(r"\bstlrb\s+wzr,\s*\[x8\]", ARM)
    x64_cas = re.findall(r"\bcmpxchgb\b", X64)
    if len(arm_cas) != 8 or len(arm_releases) != 8 or len(x64_cas) != 8:
        raise AssertionError(
            "cross-ABI eight-string XOR-once lock protocol "
            f"(ARM CAS={len(arm_cas)}, releases={len(arm_releases)}, "
            f"x86 CAS={len(x64_cas)})"
        )
    print("cross-ABI eight-string XOR-once lock protocol: PASS")

    require(
        ARM,
        r"2e0e4:.*bl\s+0x139e10.*"
        r"2e0e8:.*0x143000.*2e0ec:.*#0x8d0.*"
        r"2e0f0:.*0x143000.*2e0f4:.*#0x690.*"
        r"2e108:.*stp\s+x11,\s*x8,\s*\[x19\].*"
        r"2e10c:.*0x143000.*2e110:.*#0x6b0.*"
        r"2e114:.*0x143000.*2e118:.*#0x8b0.*"
        r"2e11c:.*mov\s+w1,\s*#0x5.*"
        r"2e124:.*str\s+w9,\s*\[x19,\s*#0xa8\].*"
        r"2e128:.*stp\s+x10,\s*x8,\s*\[x19,\s*#0x1f8\].*"
        r"2e134:.*stp\s+x10,\s*x11,\s*\[x19,\s*#0xf8\].*"
        r"2e140:.*str\s+w9,\s*\[x19,\s*#0x1a8\].*"
        r"2e144:.*str\s+x8,\s*\[x19,\s*#0x208\].*"
        r"2e148:.*str\s+x8,\s*\[x19,\s*#0x308\].*"
        r"2e150:.*str\s+x11,\s*\[x19,\s*#0x300\].*"
        r"2e154:.*#0x900.*2e15c:.*#0x918.*"
        r"2e160:.*str\s+w9,\s*\[x19,\s*#0x2a8\].*"
        r"2e164:.*str\s+x10,\s*\[x19,\s*#0x2f8\].*"
        r"2e168:.*str\s+w9,\s*\[x19,\s*#0x3a8\].*"
        r"2e16c:.*str\s+x10,\s*\[x19,\s*#0x3f8\].*"
        r"2e170:.*stp\s+x11,\s*x8,\s*\[x21,\s*#-0x100\].*"
        r"2e174:.*stur\s+w9,\s*\[x21,\s*#-0x58\].*"
        r"2e178:.*stur\s+x10,\s*\[x21,\s*#-0x8\].*"
        r"2e17c:.*sturh\s+wzr.*2e180:.*bl\s+0x24444.*"
        r"2e184:.*ldurh\s+w8.*2e194:.*cset\s+w0,\s*ne",
        "ARM64 five-record layout, batch call and count-to-bool return",
    )
    require(
        X64,
        r"2da83:.*callq\s+0x132840.*"
        r"2da88:.*0x13c060.*2da97:.*0x13c2a0.*"
        r"2dabc:.*0x13c280.*2dacb:.*-0x3f8.*"
        r"2dae3:.*0x13c080.*2daf2:.*0x13c2a8.*"
        r"2db11:.*0x13c2b0.*2db20:.*-0x1f8.*"
        r"2db38:.*0x13c2d0.*2db47:.*0x13c2e8.*"
        r"2db66:.*pushq\s+\$0x5.*2db6f:.*callq\s+0x2702f.*"
        r"2db74:.*cmpw\s+\$0x0.*2db7a:.*setne\s+%al",
        "x86_64 five-record layout, batch call and count-to-bool return",
    )
    print("cross-ABI five-record layout and count-to-bool return: PASS")

    require(
        CALLER,
        r"fb24:.*bl\s+0x2cc9c.*fb28:.*tst\s+w0,\s*#0x1",
        "sole caller and boolean branch",
    )
    require(
        CALLER,
        r"f9dc:.*mov\s+w1,\s*#0x2c",
        "correction 0x2c",
    )
    print("environment dispatcher correction 0x2c edge: PASS")

    for symbol in (
        "krecoveredmanufacturerproperty2cc9c",
        "krecoveredvendormanufacturerproperty2cc9c",
        "krecoveredmodelproperty2cc9c",
        "krecoveredvendormodelproperty2cc9c",
        "krecovereddisplayidproperty2cc9c",
        "krecoveredminicalmarker2cc9c",
        "krecoveredvcloudmarker2cc9c",
        "krecoveredscorpiomarker2cc9c",
        "runrecoveredminicalvcloudscorpioprobe2cc9c",
        "recoveredminicalvcloudscorpioprobe2cc9cregression",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ symbol {symbol}")
    require(
        CPP,
        r"std::array<recovereddescriptorbatchrecord24444,\s*5>\s+records.*"
        r"records\[0\]\.descriptorkinds\[0\]\s*=\s*3.*"
        r"records\[1\]\.descriptorkinds\[0\]\s*=\s*3.*"
        r"records\[2\]\.descriptorkinds\[0\]\s*=\s*3.*"
        r"records\[3\]\.descriptorkinds\[0\]\s*=\s*3.*"
        r"records\[4\]\.descriptorkinds\[0\]\s*=\s*3.*"
        r"std::uint16_t\s+matchcount\s*=\s*0.*"
        r"runrecovereddescriptorbatch24444\(records\.data\(\),\s*records\.size\(\).*"
        r"return\s+matchcount\s*!=\s*0",
        "C++ five-record batch and boolean return",
    )
    require(
        CPP,
        r"if\s*\(!recoveredminicalvcloudscorpioprobe2cc9cregression\(\)\)",
        "top-level regression guard",
    )

    row = inventory_row(0x2CC9C)
    if row["status"] != "recovered" or row["reachable"] != "yes":
        raise AssertionError(f"0x2cc9c recovered JNI coverage: {row}")
    print("C++ implementation, regression and recovered coverage: PASS")


if __name__ == "__main__":
    main()
