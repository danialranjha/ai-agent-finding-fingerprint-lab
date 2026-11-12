"""Run focused tests and two actual source faults in owned temporary copies."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNNER = '''import io,json,unittest
suite=unittest.defaultTestLoader.discover('.',pattern='test_experiment.py')
r=unittest.TextTestRunner(stream=io.StringIO()).run(suite)
print(json.dumps(dict(tests=r.testsRun,failures=len(r.failures),errors=len(r.errors),skipped=len(r.skipped))))
'''


def test_at(path):
    result = subprocess.run([sys.executable, "-B", "-c", RUNNER], cwd=path, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def main():
    baseline = test_at(ROOT)
    assert baseline["tests"] == 12 and not any(baseline[k] for k in ("failures", "errors", "skipped")), baseline
    mutations = []
    for name, old, new in [
        ("put_line_in_structural_key", 'if method == "structural":\n        return base',
         'if method == "structural":\n        return base + [location["line"]]'),
        ("omit_weakness_class", 'base = [path, symbol, weakness_class]', 'base = [path, symbol]'),
    ]:
        with tempfile.TemporaryDirectory(prefix="finding-key-check-") as tmp:
            tmp = Path(tmp)
            text = (ROOT / "experiment.py").read_text()
            assert text.count(old) == 1
            (tmp / "experiment.py").write_text(text.replace(old, new))
            shutil.copyfile(ROOT / "test_experiment.py", tmp / "test_experiment.py")
            result = test_at(tmp)
            assert result["tests"] == baseline["tests"] and result["failures"] > 0 and result["errors"] == 0, result
            mutations.append({"name": name, **result, "detected": True})
    data = {"baseline": baseline, "mutations": mutations}
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/checks.json").write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps(data))


if __name__ == "__main__":
    main()
