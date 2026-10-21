"""The scanner must never execute code, spawn processes or touch the network."""

import ast
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / "src" / "php_ini_audit"
FORBIDDEN_MODULES = {"subprocess", "socket", "urllib", "http", "ftplib", "ctypes", "importlib", "pty", "multiprocessing"}
FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__", "breakpoint"}
FORBIDDEN_OS = {"system", "popen", "fork", "forkpty", "startfile", "posix_spawn", "posix_spawnp", "kill"}
FORBIDDEN_OS_PREFIXES = ("exec", "spawn")


class SafetyTest(unittest.TestCase):
    def test_no_execution_primitives(self):
        problems = []
        for path in SOURCE.rglob("*.py"):
            tree = ast.parse(path.read_text(), str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    modules = [(node.module or "").split(".")[0]]
                else:
                    modules = []
                problems += [f"{path.name}: import {m}" for m in modules if m in FORBIDDEN_MODULES]
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name) and func.id in FORBIDDEN_BUILTINS:
                        problems.append(f"{path.name}:{node.lineno}: {func.id}()")
                    if (
                        isinstance(func, ast.Attribute)
                        and isinstance(func.value, ast.Name)
                        and func.value.id == "os"
                        and (func.attr in FORBIDDEN_OS or func.attr.startswith(FORBIDDEN_OS_PREFIXES))
                    ):
                        problems.append(f"{path.name}:{node.lineno}: os.{func.attr}()")
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
