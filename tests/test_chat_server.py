import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ChatServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.chat = load_module(
            "test_chat_deploy", ROOT / "modules/chat-server/deploy_chat.py")
        self.package = self.base / self.chat.TAK_DEB_NAME
        self.package.write_bytes(b"pinned-tak-package")
        self.package_hash = hashlib.sha256(self.package.read_bytes()).hexdigest()

    def tak_config(self):
        return {
            "provider": "azure",
            "provider_workload": "chat",
            "deployment_id": "tak-test",
            "server_type": "tak",
            "tak_deb_path": str(self.package),
            "tak_deb_sha256": self.package_hash,
            "tak_admin_name": "admin",
            "tak_client_name": "operator",
            "tak_ca_name": "c2itall-tak-test",
            "tak_cert_password": "ClientPassword-123456",
            "tak_ca_password": "CaPassword-123456789",
            "tak_artifact_dir": str(self.base / "artifacts"),
        }

    def test_tak_deploy_uses_same_provider_lifecycle_and_addons(self):
        config = self.tak_config()
        phantom = mock.Mock()
        phantom.deploy.return_value = True
        phantom.run_playbook.return_value = True
        with mock.patch.object(self.chat, "_load_phantom", return_value=phantom):
            self.assertTrue(self.chat.deploy_chat(config))
        phantom.deploy.assert_called_once_with(
            "tak", config, service_playbook=self.chat.TAK_PLAYBOOK)
        phantom.run_playbook.assert_called_once_with(self.chat.ADDONS_PLAYBOOK, config)
        phantom.save_deploy_info.assert_called_once_with(config)
        self.assertEqual(config["provider_workload"], "chat")
        self.assertEqual(config["deployment_type"], "chat_tak")
        self.assertEqual(os.stat(config["tak_artifact_dir"]).st_mode & 0o777, 0o700)

    def test_tak_validation_is_pinned_and_fails_before_provisioning(self):
        config = self.tak_config()
        config["tak_deb_sha256"] = "0" * 64
        phantom = mock.Mock()
        with mock.patch.object(self.chat, "_load_phantom", return_value=phantom):
            with self.assertRaisesRegex(ValueError, "checksum"):
                self.chat.deploy_chat(config)
        phantom.deploy.assert_not_called()

        config = self.tak_config()
        config["tak_client_name"] = "../../client"
        with self.assertRaisesRegex(ValueError, "tak_client_name"):
            self.chat._validate_tak_config(config)

    def test_official_tak_playbook_has_health_idempotence_and_secret_controls(self):
        playbook = self.chat.TAK_PLAYBOOK.read_text()
        for expected in (
            "postgresql-15-postgis-3", "openjdk-17-jdk", "tak_deb_sha256",
            "creates: /opt/tak/certs/files/ca.pem", "UserManager.jar",
            "https://127.0.0.1:8443/Marti/api/version", "mode: \"0600\"",
            "tak-connection-{{ deployment_id }}.zip", "no_log: true",
        ):
            self.assertIn(expected, playbook)
        self.assertNotIn("atakatak", playbook)
        self.assertNotIn("protocol: udp\n        port: \"8087\"", playbook)


class TakBuilderTests(unittest.TestCase):
    def test_import_records_checksum_and_owner_only_artifact(self):
        builder = load_module(
            "test_tak_builder", ROOT / "scripts/build_tak_server.py")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source.deb"
            source.write_bytes(b"tak")
            expected = hashlib.sha256(b"tak").hexdigest()
            artifact, manifest = builder.import_artifact(
                source, base / "output", expected)
            self.assertEqual(artifact.name, builder.DEB_NAME)
            self.assertEqual(os.stat(artifact).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(manifest).st_mode & 0o777, 0o600)
            data = json.loads(manifest.read_text())
            self.assertEqual(data["artifact_sha256"], expected)
            self.assertEqual(data["source_commit"], builder.SOURCE_COMMIT)
            self.assertEqual(data["patch_sha256"], builder.PATCH_SHA256)
            builder.validate_patch()


if __name__ == "__main__":
    unittest.main()
