import ast
import json
import unittest
from pathlib import Path

files = sorted(Path("fris_reverse").glob("*.py"))
result = {"python_files": len(files), "source_lines": 0, "functions": 0}
for path in files:
    text = path.read_text(encoding="utf-8")
    result["source_lines"] += len(text.splitlines())
    result["functions"] += sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(ast.parse(text)))
result["test_cases"] = unittest.defaultTestLoader.discover("tests").countTestCases()
print(json.dumps(result, sort_keys=True))
print("::notice title=Source metrics::" + json.dumps(result, sort_keys=True))
