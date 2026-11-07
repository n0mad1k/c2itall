"""Cross-provider playbook parsing regression tests."""

from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROVIDER_DIRS = ("AWS", "Linode", "FlokiNET")
HOSTS_PATTERN = re.compile(r"^\s*-?\s*hosts:", re.MULTILINE)


class ProviderPlaybookSyntaxTests(unittest.TestCase):
    def test_all_top_level_provider_playbooks_parse(self):
        ansible_playbook = shutil.which("ansible-playbook")
        self.assertIsNotNone(ansible_playbook, "ansible-playbook is required")

        playbooks = []
        for provider in PROVIDER_DIRS:
            for path in sorted((ROOT / "providers" / provider).glob("*.yml")):
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


if __name__ == "__main__":
    unittest.main()
