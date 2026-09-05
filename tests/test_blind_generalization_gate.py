import importlib.util
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
SPEC = importlib.util.spec_from_file_location(
    "blind_eval", ROOT / "tests" / "run_blind_generalization_eval.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class TestBlindGeneralizationStrictGate(unittest.TestCase):
    def test_blind_generalization_strict_gate(self):
        summary = MODULE.run_blind_evaluation()
        metrics = summary["accuracy_metrics"]
        self.assertEqual(summary["cases_evaluated"], 21)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["false_negatives"], 0)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertGreaterEqual(summary["render_performance"]["pages_recovered"], 2)
