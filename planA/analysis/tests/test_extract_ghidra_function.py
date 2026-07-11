import importlib.util
import pathlib
import subprocess
import tempfile
import unittest


WORKSPACE = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = WORKSPACE / "analysis" / "scripts" / "extract_ghidra_function.py"


def load_script_module():
    spec = importlib.util.spec_from_file_location("extract_ghidra_function", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ExtractGhidraFunctionTest(unittest.TestCase):
    def test_extracts_one_balanced_function(self):
        extractor = load_script_module()
        source = """
void before(void) { return; }

// evidence comment
void target(int value)
{
  if (value) {
    value--;
  }
}

void after(void) { return; }
"""

        extracted = extractor.extract_function(source, "target")

        self.assertIn("// evidence comment", extracted)
        self.assertIn("void target(int value)", extracted)
        self.assertIn("value--;", extracted)
        self.assertNotIn("void before", extracted)
        self.assertNotIn("void after", extracted)

    def test_extracts_real_map_get_helper_without_neighbor(self):
        extractor = load_script_module()
        source = (WORKSPACE / "libsig.txt").read_text(encoding="utf-8")

        extracted = extractor.extract_function(source, "FUN_0018b510")

        self.assertIn("void FUN_0018b510", extracted)
        self.assertIn("*param_2 + 0x540", extracted)
        self.assertIn("*param_2 + 0x548", extracted)
        self.assertNotIn("void FUN_0018be4c", extracted)

    def test_missing_function_is_an_error(self):
        extractor = load_script_module()
        with self.assertRaisesRegex(ValueError, "not found"):
            extractor.extract_function("void present(void) {}", "missing")

    def test_script_is_directly_executable_on_current_host(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "sample.c"
            source.write_text(
                "void before(void) {}\nvoid target(void) { return; }\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [str(SCRIPT), str(source), "target"],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("void target(void)", result.stdout)


if __name__ == "__main__":
    unittest.main()
