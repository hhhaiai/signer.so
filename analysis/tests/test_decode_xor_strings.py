import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest


WORKSPACE = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = WORKSPACE / "analysis" / "scripts" / "decode_xor_strings.py"
ARM64_SAMPLE = WORKSPACE / "jni" / "arm64-v8a" / "libsigner.so"


def load_script_module():
    spec = importlib.util.spec_from_file_location("decode_xor_strings", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DecodeXorStringsTest(unittest.TestCase):
    def test_decodes_known_environment_and_sandbox_vectors(self):
        decoder = load_script_module()

        environment = decoder.xor_bytes(
            bytes.fromhex("7378607f6479787b73786216"), 0x16
        )
        sandbox = decoder.xor_bytes(bytes.fromhex("06141b11171a0d75"), 0x75)

        self.assertEqual(environment, b"environment\0")
        self.assertEqual(sandbox, b"sandbox\0")

    def test_reads_rva_through_elf_load_segments(self):
        decoder = load_script_module()
        image = decoder.ElfImage(ARM64_SAMPLE)

        self.assertEqual(
            image.read_rva(0x11E730, 12),
            bytes.fromhex("7378607f6479787b73786216"),
        )
        self.assertEqual(image.rva_to_offset(0x11E730), 0x116730)

    def test_catalog_decodes_only_declared_evidence_records(self):
        decoder = load_script_module()
        catalog = decoder.build_catalog(WORKSPACE / "jni")
        records = {record["id"]: record for record in catalog["records"]}

        self.assertEqual(
            catalog["sample"]["artifact"],
            "com.adjust.signature:adjust-android-signature:3.62.0",
        )
        self.assertEqual(records["environment_key"]["plaintext"], "environment")
        self.assertEqual(records["sandbox_value"]["plaintext"], "sandbox")
        self.assertEqual(
            records["sign_begin_log"]["plaintext"],
            "Signing all the parameters begin",
        )
        self.assertEqual(
            records["map_get_descriptor"]["plaintext"],
            "(Ljava/lang/Object;)Ljava/lang/Object;",
        )
        self.assertEqual(records["tracer_pid_label"]["plaintext"], "TracerPid:")
        self.assertEqual(records["proc_status_format"]["plaintext"], "/proc/%d/status")
        self.assertEqual(records["map_get_name"]["plaintext"], "get")
        self.assertEqual(records["timestamp_format"]["plaintext"], "%Y-%m-%dT%H:%M:%S")
        self.assertEqual(records["timezone_format"]["plaintext"], "%z")
        self.assertEqual(records["timestamp_log_format"]["plaintext"], "%s: %s.%03dZ%s")

        arm64_map_get = next(
            observation
            for observation in records["map_get_name"]["observations"]
            if observation["abi"] == "arm64-v8a"
        )
        self.assertEqual(arm64_map_get["rva"], "0x11df2c")
        arm64_timezone = next(
            observation
            for observation in records["timezone_format"]["observations"]
            if observation["abi"] == "arm64-v8a"
        )
        self.assertEqual(arm64_timezone["rva"], "0x11ef44")

        arm64_observation = next(
            observation
            for observation in records["environment_key"]["observations"]
            if observation["abi"] == "arm64-v8a"
        )
        self.assertEqual(arm64_observation["rva"], "0x11e730")
        self.assertEqual(arm64_observation["file_offset"], "0x116730")
        self.assertEqual(arm64_observation["xor_key"], "0x16")
        self.assertEqual(arm64_observation["decoded_hex"], "656e7669726f6e6d656e7400")
        self.assertEqual(
            records["environment_key"]["arm64_guard"]["atomic_word_rva"],
            "0x11fa58",
        )
        self.assertEqual(
            records["environment_key"]["arm64_guard"]["initialized_byte_rva"],
            "0x11fa65",
        )

        for record in catalog["records"]:
            self.assertNotIn("guess", record)
            self.assertIn(record["evidence"], {"verified", "corroborated"})
            for observation in record["observations"]:
                self.assertTrue(observation["verified_against_sample"])

    def test_cli_writes_deterministic_json(self):
        decoder = load_script_module()
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "strings.json"
            exit_code = decoder.main(
                ["--sample-root", str(WORKSPACE / "jni"), "--output", str(output)]
            )
            first = output.read_text(encoding="utf-8")
            exit_code_again = decoder.main(
                ["--sample-root", str(WORKSPACE / "jni"), "--output", str(output)]
            )
            second = output.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertEqual(exit_code_again, 0)
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)["schema"], "libsigner.xor-strings/v1")

    def test_script_is_directly_executable_on_current_host(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "strings.json"
            result = subprocess.run(
                [
                    str(SCRIPT),
                    "--sample-root",
                    str(WORKSPACE / "jni"),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
