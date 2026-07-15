#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "batch"
CLASSPATH = (
    str(ROOT / "unidbg-adjust-runner/target/classes")
    + ":"
    + (ROOT / "unidbg-adjust-runner/target/runtime-classpath.txt").read_text().strip()
)


def normalized_job(value):
    value = json.loads(json.dumps(value))
    value.pop("expectedResult", None)
    value.pop("expectedResultFile", None)
    value.get("device", {}).get("runtime", {}).pop("backend", None)
    return value


def discover_pairs():
    pairs = []
    seen = set()
    for recovered in (ROOT / ".omx").rglob("*.json"):
        if "/logs/" in recovered.as_posix():
            continue
        names = []
        if "_recovered" in recovered.name:
            names.extend([
                recovered.name.replace("_recovered", ""),
                recovered.name.replace("_recovered", "_unidbg"),
            ])
        if "-recovered" in recovered.name:
            names.extend([
                recovered.name.replace("-recovered", ""),
                recovered.name.replace("-recovered", "-unidbg"),
            ])
        for name in names:
            original = recovered.with_name(name)
            if not original.is_file():
                continue
            key = (original, recovered)
            if key in seen:
                break
            seen.add(key)
            left = json.loads(original.read_text())
            right = json.loads(recovered.read_text())
            if "device" not in left or "sign" not in left:
                break
            if normalized_job(left) == normalized_job(right):
                pairs.append(key)
            break
    return sorted(pairs)


def run_job(job):
    command = [
        "java",
        "-XX:TieredStopAtLevel=1",
        "-Dorg.slf4j.simpleLogger.defaultLogLevel=error",
        "-cp",
        CLASSPATH,
        "local.SignerOneClick",
        str(job),
        str(ROOT),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=90,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"exit={completed.returncode}\n{completed.stdout}")
    line = next(
        (line for line in completed.stdout.splitlines()
         if line.startswith("SIGNER_RESULT_JSON=")),
        None,
    )
    if line is None:
        raise RuntimeError("missing SIGNER_RESULT_JSON\n" + completed.stdout)
    return json.loads(line.split("=", 1)[1]), completed.stdout


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    pairs = discover_pairs()
    failures = []
    results = []
    print(f"PAIR_COUNT={len(pairs)}", flush=True)
    for index, (original_job, recovered_job) in enumerate(pairs, 1):
        label = original_job.relative_to(ROOT).as_posix()
        print(f"[{index}/{len(pairs)}] {label}", flush=True)
        try:
            original, original_log = run_job(original_job)
            recovered, recovered_log = run_job(recovered_job)
            exact = original == recovered
            signature_exact = (
                original.get("rawSignatureHex") == recovered.get("rawSignatureHex")
            )
            item = {
                "originalJob": str(original_job.relative_to(ROOT)),
                "recoveredJob": str(recovered_job.relative_to(ROOT)),
                "exact": exact,
                "signatureExact": signature_exact,
                "originalLength": len(bytes.fromhex(original.get("rawSignatureHex", ""))),
                "recoveredLength": len(bytes.fromhex(recovered.get("rawSignatureHex", ""))),
            }
            results.append(item)
            stem = f"{index:02d}-{original_job.stem}"
            (OUT / f"{stem}-original.log").write_text(original_log)
            (OUT / f"{stem}-recovered.log").write_text(recovered_log)
            print(
                f"  exact={exact} signatureExact={signature_exact} "
                f"length={item['originalLength']}/{item['recoveredLength']}",
                flush=True,
            )
            if not exact:
                failures.append(item)
        except Exception as error:
            item = {
                "originalJob": str(original_job.relative_to(ROOT)),
                "recoveredJob": str(recovered_job.relative_to(ROOT)),
                "error": str(error),
            }
            results.append(item)
            failures.append(item)
            print("  ERROR " + str(error).splitlines()[0], flush=True)
    (OUT / "summary.json").write_text(json.dumps(results, indent=2))
    print(f"PASS={len(results) - len(failures)} FAIL={len(failures)}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
