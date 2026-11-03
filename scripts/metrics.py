"""Reproducible source metrics, not an assertion of software quality."""
import ast
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
files = sorted(p for folder in ("fris_reverse", "tests", "scripts") for p in (root / folder).glob("*.py"))
counts = {p.relative_to(root).as_posix(): len(p.read_text(encoding="utf-8").splitlines()) for p in files}
tests = sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_") for p in files if p.parent.name == "tests" for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))))
print(json.dumps({"python_files": len(files), "python_lines": sum(counts.values()), "test_methods": tests, "files": counts}, indent=2))
