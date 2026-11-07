"""Fail-closed behavior for the WEBRUNNER live-test harness."""

import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "webrunner_live_harness", ROOT / "smoke_test_webrunner.py")
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class WebrunnerLiveHarnessTests(unittest.TestCase):
    def test_preview_is_non_mutating(self):
        with mock.patch.object(
                HARNESS, "generate_deployment_id",
                return_value="preview-test"), mock.patch.object(
                    HARNESS, "set_provider_environment") as environment, \
                mock.patch.object(HARNESS, "generate_ssh_key") as key, \
                mock.patch.object(HARNESS, "execute_playbook") as playbook, \
                mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(HARNESS.main([]), 0)
        self.assertIn("preview only", output.getvalue())
        environment.assert_not_called()
        key.assert_not_called()
        playbook.assert_not_called()

    def test_owned_inventory_uses_exact_test_identity(self):
        inventory = [
            {"id": 1, "label": "wr-smoke-test-id-01", "tags": []},
            {"id": 2, "label": "other", "tags": ["test-id"]},
            {"id": 3, "label": "foreign", "tags": []},
        ]
        keys = [
            {"id": 4, "label": "wr-smoke-test-id"},
            {"id": 5, "label": "wr-smoke-other"},
        ]
        with mock.patch.object(
                HARNESS, "linode_pages", side_effect=[inventory, keys]):
            instances, ssh_keys = HARNESS.owned_linode_inventory(
                "token", "test-id", "wr-smoke-test-id")
        self.assertEqual([item["id"] for item in instances], [1, 2])
        self.assertEqual([item["id"] for item in ssh_keys], [4])

    def test_cleanup_deletes_owned_objects_and_proves_absence(self):
        with mock.patch.object(
                HARNESS, "owned_linode_inventory", side_effect=[
                    ([{"id": 10}], [{"id": 20}]),
                    ([], []),
                ]) as inventory, mock.patch.object(
                    HARNESS, "linode_request") as api:
            self.assertTrue(HARNESS.cleanup_linode(
                "token", "test-id", "wr-smoke-test-id", timeout=0))
        self.assertEqual(inventory.call_count, 2)
        self.assertEqual(api.call_args_list, [
            mock.call("token", "/linode/instances/10", "DELETE"),
            mock.call("token", "/profile/sshkeys/20", "DELETE"),
        ])

    def test_activation_without_credentials_stops_before_local_or_cloud_work(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(HARNESS, "set_provider_environment"), \
                mock.patch.object(HARNESS, "generate_ssh_key") as key, \
                mock.patch.object(HARNESS, "execute_playbook") as playbook, \
                mock.patch("sys.stderr", new_callable=io.StringIO) as error:
            result = HARNESS.main([
                "--activate", "--operator-ip", "8.8.8.8",
                "--deployment-id", "missing-creds",
            ])
        self.assertEqual(result, 2)
        self.assertIn("credentials are unavailable", error.getvalue())
        key.assert_not_called()
        playbook.assert_not_called()

    def test_activation_refuses_preexisting_identity_before_creating_inputs(self):
        def environment(_):
            os.environ["LINODE_TOKEN"] = "test-token"

        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(
                    HARNESS, "set_provider_environment", side_effect=environment), \
                mock.patch.object(
                    HARNESS, "owned_linode_inventory",
                    return_value=([{"id": 1}], [])), \
                mock.patch.object(HARNESS, "generate_ssh_key") as key, \
                mock.patch.object(HARNESS, "execute_playbook") as playbook, \
                mock.patch("sys.stderr", new_callable=io.StringIO) as error:
            result = HARNESS.main([
                "--activate", "--operator-ip", "8.8.8.8",
                "--deployment-id", "existing-identity",
            ])
        self.assertEqual(result, 2)
        self.assertIn("refusing to claim", error.getvalue())
        key.assert_not_called()
        playbook.assert_not_called()

    def test_activated_run_removes_local_inputs_after_verified_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            private = base / "test-key"

            def make_key(_):
                private.write_text("private")
                Path(str(private) + ".pub").write_text("public")
                return str(private)

            def environment(_):
                os.environ["LINODE_TOKEN"] = "test-token"

            with mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(HARNESS, "ROOT", base), \
                    mock.patch.object(
                        HARNESS, "set_provider_environment",
                        side_effect=environment), \
                    mock.patch.object(
                        HARNESS, "generate_ssh_key", side_effect=make_key), \
                    mock.patch.object(
                        HARNESS, "owned_linode_inventory", return_value=([], [])), \
                    mock.patch.object(HARNESS, "setup_logging"), \
                    mock.patch.object(
                        HARNESS, "execute_playbook", return_value=True) as playbook, \
                    mock.patch.object(
                        HARNESS, "cleanup_linode", return_value=True) as cleanup:
                result = HARNESS.main([
                    "--activate", "--operator-ip", "8.8.8.8",
                    "--deployment-id", "verified-cleanup",
                ])

            self.assertEqual(result, 0)
            playbook.assert_called_once()
            cleanup.assert_called_once_with(
                "test-token", "verified-cleanup", "wr-smoke-verified-cleanup")
            self.assertFalse(private.exists())
            self.assertFalse(Path(str(private) + ".pub").exists())
            self.assertFalse(
                (base / "logs/node_chunks_verified-cleanup.json").exists())


if __name__ == "__main__":
    unittest.main()
