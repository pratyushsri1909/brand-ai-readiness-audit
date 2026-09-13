import ast
import os
import unittest

# global getaddrinfo mock for .test domains
import socket
if not hasattr(socket, '_real_c_getaddrinfo'):
    socket._real_c_getaddrinfo = socket.getaddrinfo
def _fake_getaddrinfo(host, port, *args, **kwargs):
    if host and (host.endswith('.test') or host.endswith('.example') or host.endswith('.invalid')):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port or 0))]
    return socket._real_c_getaddrinfo(host, port, *args, **kwargs)
socket.getaddrinfo = _fake_getaddrinfo


from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestSyntaxCompatibility(unittest.TestCase):
    def test_all_python_files_ast_parse(self):
        """Verify that every python file in the workspace parses cleanly with ast.parse()."""
        py_files = []
        for root, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in {"__pycache__", ".pytest_cache", ".git"}]
            for file in files:
                if file.endswith(".py"):
                    py_files.append(Path(root) / file)

        self.assertGreater(len(py_files), 5, "Should find multiple Python files")

        errors = []
        for py_path in py_files:
            try:
                content = py_path.read_text(encoding="utf-8")
                tree = ast.parse(content, filename=str(py_path))
                self.assertIsInstance(tree, ast.Module)
            except SyntaxError as e:
                errors.append(f"SyntaxError in {py_path.relative_to(ROOT)}: {e}")

        self.assertEqual(errors, [], f"Syntax errors found: {errors}")

    def test_entrypoint_fstrings_no_pre312_syntax_hazards(self):
        """Verify that run_audit.py AST has no nested subscript accesses inside FormattedValues."""
        entrypoint = ROOT / "skills/audit-orchestrator/scripts/run_audit.py"
        content = entrypoint.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(entrypoint))

        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                for value in node.values:
                    if isinstance(value, ast.FormattedValue):
                        self.assertNotIsInstance(
                            value.value,
                            ast.Subscript,
                            f"Found direct Subscript inside f-string in run_audit.py line {getattr(value, 'lineno', '?')} - extract to local variable for 3.10 compatibility"
                        )


if __name__ == "__main__":
    unittest.main()
