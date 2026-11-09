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

    def test_attack_box_handles_packages_missing_from_current_cloud_images(self):
        content = (ROOT / "modules/attack-box/tasks/configure_attack_box.yml").read_text()
        base = content[content.index("Select required packages for the attack-box image"):
                       content.index("register: apt_install_result")]
        self.assertNotIn("libdnet-dev", content)
        self.assertIn("libdumbnet-dev", content)
        self.assertNotIn("- outguess", base)
        self.assertNotIn("- bless", base)
        self.assertIn("Check availability of optional attack-box packages", content)
        self.assertIn("Install available optional attack-box packages", content)
        self.assertIn("attack_box_kali_only_packages:\n      - recon-ng", content)
        self.assertIn("Install base packages in one transaction", content)
        self.assertNotIn('name: "{{ item }}"', base)

if __name__ == "__main__":
    unittest.main()
