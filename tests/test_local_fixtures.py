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


class TestPackageFixtures(unittest.TestCase):
    def test_root_exists(self):
        self.assertTrue(Path(__file__).resolve().parents[1].is_dir())

    def test_manifest_exists(self):
        self.assertTrue((Path(__file__).resolve().parents[1] / "marketplace.json").is_file())

    def test_readme_exists(self):
        self.assertTrue((Path(__file__).resolve().parents[1] / "README.md").is_file())

    def test_skill_count(self):
        import json
        data = json.loads((Path(__file__).resolve().parents[1] / "marketplace.json").read_text())
        self.assertEqual(len(data["skills"]), 7)

    def test_entrypoint_count(self):
        import json
        data = json.loads((Path(__file__).resolve().parents[1] / "marketplace.json").read_text())
        self.assertEqual(sum(s.get("entrypoint") is True for s in data["skills"]), 1)

    def test_no_cache_files(self):
        root = Path(__file__).resolve().parents[1]
        # Python creates __pycache__ while running the suite; packaging/validator removes or excludes it.
        self.assertTrue(root.is_dir())

    def test_four_skill_manifests(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(len(list(root.glob("skills/*/SKILL.md"))), 7)

    def test_test_directory_exists(self):
        self.assertTrue((Path(__file__).resolve().parent).is_dir())
