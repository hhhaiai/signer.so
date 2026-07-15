#!/usr/bin/env python3
"""Recover the arm64 Map metadata helpers without executing libsigner.so."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
DISASM = ROOT / ".omx/libsigner-arm64-objdump.txt"
OUTPUT = Path(__file__).with_name("arm64-map-metadata-jni.md")

LOAD_BIAS = 0x8000


def read_vma(blob: bytes, vma: int, size: int) -> bytes:
    return blob[vma - LOAD_BIAS : vma - LOAD_BIAS + size]


def decode_c_string(blob: bytes, vma: int, mask: int) -> str:
    decoded = bytearray()
    for value in read_vma(blob, vma, 256):
        value ^= mask
        if value == 0:
            return decoded.decode("ascii")
        decoded.append(value)
    raise ValueError(f"unterminated string at 0x{vma:x}")


def require(pattern: str, text: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing {description}: {pattern}")


def main() -> None:
    blob = SO.read_bytes()
    disasm = DISASM.read_text()

    metadata = [
        ("headers_id", 0x142EA8, 0x26, "9", 0x142EB4, 0xA4, 0xC544),
        ("native_version", 0x142EB8, 0x7C, "3.67.0", 0x142EC8, 0xD9, 0xBFFC),
        ("adj_signing_id", 0x142ED0, 0x11, "1400000", 0x142EA0, 0x4D, 0xC7F4),
        ("algorithm", 0x142EE0, 0xCC, "adj8", 0x142EEC, 0xDB, 0xC6A4),
    ]

    decoded = []
    for expected_key, key_vma, key_mask, expected_value, value_vma, value_mask, call in metadata:
        key = decode_c_string(blob, key_vma, key_mask)
        value = decode_c_string(blob, value_vma, value_mask)
        if (key, value) != (expected_key, expected_value):
            raise AssertionError((key, value, expected_key, expected_value))
        decoded.append((key, key_vma, key_mask, value, value_vma, value_mask, call))

    # Four statically visible calls in the metadata orchestrator all target the
    # same Java Map.put helper.  The call order is flattened, so addresses are
    # evidence of the pair, not of runtime sequence.
    call_patterns = {
        0xBFFC: (0x142EB8, 0x142EC8),
        0xC544: (0x142EA8, 0x142EB4),
        0xC6A4: (0x142EE0, 0x142EEC),
        0xC7F4: (0x142ED0, 0x142EA0),
    }
    for call, (key_vma, value_vma) in call_patterns.items():
        page = key_vma & ~0xFFF
        require(
            rf"(?s){call - 0x30:x}:.*?adrp\s+x3, 0x{page:x}.*?"
            rf"add\s+x3, x3, #0x{key_vma & 0xFFF:x}.*?"
            rf"adrp\s+x4, 0x{value_vma & ~0xFFF:x}.*?"
            rf"add\s+x4, x4, #0x{value_vma & 0xFFF:x}.*?"
            rf"{call:x}:.*?bl\s+0x9954c",
            disasm,
            f"Map.put pair at 0x{call:x}",
        )

    method_strings = [
        ("put", 0x144A50, 0xE9),
        ("(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", 0x144A60, 0x9B),
        ("containsKey", 0x145058, 0xCE),
        ("(Ljava/lang/Object;)Z", 0x145070, 0x18),
        ("get", 0x144FBC, 0x47),
        ("(Ljava/lang/Object;)Ljava/lang/Object;", 0x144AB0, 0xCB),
    ]
    for expected, vma, mask in method_strings:
        actual = decode_c_string(blob, vma, mask)
        if actual != expected:
            raise AssertionError((hex(vma), actual, expected))

    # JNINativeInterface offsets used by the three helpers.
    # 0xf8 GetObjectClass, 0x108 GetMethodID, 0x110 CallObjectMethod,
    # 0x128 CallBooleanMethod, 0x538 NewStringUTF, 0xb8 DeleteLocalRef.
    helper_requirements = [
        (0x9954C, 0x9AA5C, [0xF8, 0x108, 0x110, 0x538, 0xB8]),
        (0xACD90, 0xADBF4, [0xF8, 0x108, 0x128, 0x538, 0xB8]),
        (0xADBF4, 0xAEBF8, [0xF8, 0x108, 0x110, 0x538, 0xB8]),
    ]
    lines = disasm.splitlines()
    parsed = []
    for line in lines:
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match:
            parsed.append((int(match.group(1), 16), line))
    for start, end, offsets in helper_requirements:
        body = "\n".join(line for address, line in parsed if start <= address < end)
        for offset in offsets:
            require(rf"ldr\s+x8, \[x8, #0x{offset:x}\]", body, f"JNI offset 0x{offset:x} in 0x{start:x}")

    # The selected-value walker starts only from the decoded 100-key table and
    # contains no direct reference to the standalone adj_signing_id buffer.
    walker = "\n".join(line for address, line in parsed if 0x11BA78 <= address < 0x11D408)
    require(r"adr\s+x20, 0x145a30", walker, "100-key table base")
    require(r"bl\s+0xacd90", walker, "containsKey helper")
    require(r"bl\s+0xadbf4", walker, "get helper")
    if re.search(r"0x142ed0|#0xed0", walker):
        raise AssertionError("walker unexpectedly references adj_signing_id buffer")

    rows = []
    for key, key_vma, key_mask, value, value_vma, value_mask, call in decoded:
        rows.append(
            f"| `{key}` | `0x{key_vma:x}` / `0x{key_vma - LOAD_BIAS:x}` | "
            f"`0x{key_mask:02x}` | `{value}` | `0x{value_vma:x}` / "
            f"`0x{value_vma - LOAD_BIAS:x}` | `0x{value_mask:02x}` | `0x{call:x}` |"
        )

    OUTPUT.write_text(
        "\n".join(
            [
                "# arm64 Map metadata and JNI helper proof",
                "",
                "本报告只读取 ELF 数据和现有 objdump 文本，不加载或执行目标 SO。",
                "",
                "## Metadata pairs inserted by `0xaf3c`",
                "",
                "`0x9954c` 的 JNI 调用形态是 `Map.put(String,String)`：它使用 "
                "`GetObjectClass(0xf8)`、`GetMethodID(0x108)`、"
                "`CallObjectMethod(0x110)`、`NewStringUTF(0x538)` 和 "
                "`DeleteLocalRef(0xb8)`；其 method name/signature 解码为 "
                "`put` / `(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;`。",
                "",
                "| key | key VMA / file offset | XOR | value | value VMA / file offset | XOR | `Map.put` call |",
                "|---|---:|---:|---|---:|---:|---:|",
                *rows,
                "",
                "由于 `0xaf3c` 是 flattened state machine，call-site 地址不能当作运行顺序；"
                "但每个 call-site 的 `x3=key`、`x4=value` 配对是直接静态证据。",
                "",
                "## Selected Map-value walker helpers",
                "",
                "- `0xacd90`: method name/signature 解码为 `containsKey` / "
                "`(Ljava/lang/Object;)Z`，并使用 `CallBooleanMethod(0x128)`。",
                "- `0xadbf4`: method name/signature 解码为 `get` / "
                "`(Ljava/lang/Object;)Ljava/lang/Object;`，并使用 `CallObjectMethod(0x110)`。",
                "- `0x11ba78` 从 `0x145a30` 的 100-key CSV 表开始解析 key，逐项执行 "
                "`containsKey -> get -> callback`。",
                "",
                "## Important correction about `adj_signing_id`",
                "",
                "`0x11ba78..0x11d408` 没有引用 standalone `adj_signing_id` buffer "
                "`0x142ed0`，而 100-key 表也不包含该 key。因此 `0x11d798` 的两遍 "
                "materializer 只能证明 100-key selected Map values 的拼接，不能静态证明 "
                "`adj_signing_id` 是在这个 walker 内插入的。",
                "",
                "独立 `adj_signing_id=1400000` 的已确认角色之一，是 `0xaf3c` 通过 "
                "`Map.put` 写入 native result metadata Map；它在最终被签名 logical plaintext "
                "中的精确拼接层仍需继续从 `0x11da64 -> 0xf1ec8` 的九 descriptor 数据流证明。",
                "",
                "这不会推翻已有 exact output：当前 C++ 把该值放到已验证的位置仍能复现冻结 "
                "oracle；修正的是对 `0x11d798` 角色的过度归因。",
                "",
            ]
        )
    )
    print(f"MAP_METADATA_JNI_STATIC_OK output={OUTPUT}")


if __name__ == "__main__":
    main()
