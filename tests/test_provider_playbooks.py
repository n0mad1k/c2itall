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

    def test_linode_region_fallback_normalizes_the_first_success(self):
        playbooks = ("redirector.yml", "c2.yml", "mta.yml", "gophish.yml", "webserver.yml")
        for name in playbooks:
            with self.subTest(playbook=name):
                content = (ROOT / "providers/Linode" / name).read_text()
                self.assertIn("include_tasks: tasks/create_instance_with_fallback.yml", content)
                self.assertNotIn("fallback_regions:", content)
                self.assertNotIn("ansible_loop.index0", content)
                self.assertNotIn(".results | default([])", content)

        helper = (ROOT / "providers/Linode/tasks/create_instance_with_fallback.yml").read_text()
        candidate = (ROOT / "providers/Linode/tasks/try_instance_region.yml").read_text()
        self.assertIn("failed_when: false", helper)
        self.assertIn("include_tasks: try_instance_region.yml", helper)
        self.assertIn("when: not (linode_instance_created | bool)", helper)
        self.assertIn("Require a successful Linode region", helper)
        self.assertIn("linode_created_instance", candidate)
        self.assertIn("linode_created_region", candidate)
        self.assertEqual(candidate.count("not (linode_instance_created | bool)"), 2)

    def test_aws_cleanup_proves_absence_before_local_closeout(self):
        cleanup = (ROOT / "providers/AWS/cleanup.yml").read_text()
        for marker in (
                '"tag:deployment_id": "{{ deployment_id }}"',
                '"tag:DeploymentID": "{{ deployment_id }}"',
                "Verify current-tag instances are absent",
                "Verify historical-tag instances are absent",
                "Verify current-tag security groups are absent",
                "Verify historical-tag security groups are absent",
                "Verify current-tag VPCs are absent",
                "Verify deployment key pairs are absent",
        ):
            self.assertIn(marker, cleanup)
        self.assertLess(
            cleanup.index("Verify deployment key pairs are absent"),
            cleanup.index("Delete SSH key files"))

        attack_box = (ROOT / "providers/AWS/attack_box.yml").read_text()
        webrunner = (ROOT / "providers/webrunner.yml").read_text()
        self.assertIn('deployment_id: "{{ deployment_id }}"', attack_box)
        self.assertIn("aws_volume_size | default(64)", attack_box)
        self.assertIn("'/dev/sda1' if attack_box_type == 'ubuntu'", attack_box)
        self.assertIn("network_interfaces:", attack_box)
        self.assertNotIn("\n        network:\n", attack_box)
        self.assertIn("volume_type: gp3", attack_box)
        self.assertIn("delete_on_termination: true", attack_box)
        self.assertIn("Require enough root capacity for the full toolset", attack_box)
        self.assertIn('deployment_id: "{{ deployment_id }}"', webrunner)

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

    def test_webrunner_teardown_verifies_nodes_and_auxiliaries(self):
        playbook = (ROOT / "providers/webrunner.yml").read_text()
        for marker in (
                "Verify Linode nodes are absent",
                "Verify WEBRUNNER Linode profile keys are absent",
                "Delete AWS WEBRUNNER security groups",
                "Delete AWS WEBRUNNER key pairs",
                "Verify AWS WEBRUNNER security groups are absent",
                "Verify AWS WEBRUNNER key pairs are absent",
        ):
            self.assertIn(marker, playbook)
        teardown = playbook[playbook.index("WEBRUNNER — Teardown scan nodes"):]
        self.assertNotIn("ignore_errors", teardown)


if __name__ == "__main__":
    unittest.main()
