"""Cross-provider playbook parsing regression tests."""

from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_ROOTS = ("providers", "modules", "ghost_protocol")
HOSTS_PATTERN = re.compile(r"^\s*-?\s*hosts:", re.MULTILINE)


class ProviderPlaybookSyntaxTests(unittest.TestCase):
    def test_all_top_level_provider_playbooks_parse(self):
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")

        playbooks = []
        for root in PLAYBOOK_ROOTS:
            for path in sorted((ROOT / root).rglob("*.yml")):
                if HOSTS_PATTERN.search(path.read_text()):
                    playbooks.append(path)
            for path in sorted((ROOT / root).rglob("*.yaml")):
                if HOSTS_PATTERN.search(path.read_text()):
                    playbooks.append(path)

        self.assertTrue(playbooks, "no provider playbooks were discovered")
        for path in playbooks:
            with self.subTest(playbook=path.relative_to(ROOT)):
                result = subprocess.run(
                    [ansible_playbook, "--syntax-check", str(path)],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    result.stdout + result.stderr,
                )

    def test_linode_cleanup_requires_provider_side_absence(self):
        cleanup = (ROOT / "providers/Linode/cleanup.yml").read_text()
        for marker in (
                "Inventory Linodes before cleanup",
                "Delete deployment-owned Linodes by immutable ID",
                "Verify every owned Linode is absent",
                "Inventory Linode profile SSH keys",
                "Verify every owned Linode SSH key is absent",
                "status_code: [200, 404]",
        ):
            self.assertIn(marker, cleanup)
        self.assertNotIn("ignore_errors", cleanup)


if __name__ == "__main__":
    unittest.main()
