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
        registration = playbook.split(
            "- name: Register TAK administrator certificate", 1)[1].split(
                "\n    - name:", 1)[0]
        self.assertNotIn("--offline", registration)
        self.assertIn("chdir: /opt/tak", registration)
        self.assertIn("until: tak_admin_registration.rc == 0", registration)
        api_check = playbook.split(
            "- name: Verify TAK administration API with client certificate", 1)[1].split(
                "\n    - name:", 1)[0]
        self.assertIn("- --config", api_check)
        self.assertIn("stdin: |", api_check)
        self.assertIn('write-out = "%{http_code}"', api_check)
        self.assertIn("failed_when: false", api_check)
        self.assertIn('cert-type = "PEM"', api_check)
        self.assertIn('key-type = "PEM"', api_check)
        self.assertIn('pass = "{{ tak_cert_password }}"', api_check)
        self.assertNotIn("- --cert", api_check)
        self.assertIn("Require authenticated TAK administration API access", playbook)
        self.assertNotIn("atakatak", playbook)
        self.assertNotIn("protocol: udp\n        port: \"8087\"", playbook)


class MatrixRotationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.rotation = load_module(
            "test_matrix_rotation", ROOT / "modules/chat-server/rotate_matrix.py")
        self.state_path = self.base / "rotation.json"
        self.active = {
            "provider": "azure",
            "provider_workload": "chat",
            "deployment_id": "matrix-active",
            "deployment_type": "chat_matrix",
            "server_type": "matrix",
            "domain": "matrix-1.example.test",
            "matrix_server_name": "matrix-1.example.test",
            "matrix_admin_user": "admin",
            "matrix_admin_password": "old-secret",
            "target_host": "192.0.2.10",
            "matrix_signing_key": "a" * 64,
            "matrix_form_secret": "b" * 64,
            "matrix_macaroon_secret": "c" * 64,
        }

    def state(self, phase="active", now=100):
        return {
            "version": self.rotation.STATE_VERSION,
            "name": "team-chat",
            "phase": phase,
            "generation": 1,
            "active": dict(self.active),
            "replacement": None,
            "room_id": "!room:matrix-1.example.test",
            "domain_template": "matrix-{generation}.example.test",
            "interval_seconds": 86400,
            "grace_seconds": 3600,
            "uses_allowed": 25,
            "next_rotation_at": now,
            "teardown_at": None,
            "last_announcement": None,
        }

    def write_state(self, state):
        self.rotation._write_state(self.state_path, state)
        return self.rotation._load_state(self.state_path)

    def test_state_is_owner_only_and_status_redacts_credentials(self):
        state = self.write_state(self.state())
        self.assertEqual(os.stat(self.state_path).st_mode & 0o777, 0o600)
        rendered = json.dumps(self.rotation._status(state))
        self.assertNotIn("old-secret", rendered)
        self.assertNotIn("matrix_signing_key", rendered)

    def test_state_loader_rejects_symlinks_and_permissive_modes(self):
        self.write_state(self.state())
        link = self.base / "linked.json"
        link.symlink_to(self.state_path)
        with self.assertRaisesRegex(self.rotation.RotationError, "unsafe"):
            self.rotation._load_state(link)
        self.state_path.chmod(0o644)
        with self.assertRaisesRegex(self.rotation.RotationError, "owner-only"):
            self.rotation._load_state(self.state_path)

    def test_timer_install_rejects_symlinked_state(self):
        self.write_state(self.state())
        link = self.base / "linked.json"
        link.symlink_to(self.state_path)
        with self.assertRaisesRegex(self.rotation.RotationError, "unsafe"):
            self.rotation.install_timer("team-chat", link)

    def test_rotation_announces_limited_token_then_retires_old_server(self):
        self.write_state(self.state())
        deployed = []
        retired = []
        calls = []

        def deploy(config):
            config["target_host"] = "192.0.2.20"
            deployed.append(config["deployment_id"])
            return True

        api = {
            "login": lambda config: "access-" + config["deployment_id"],
            "create_token": lambda config, access, uses, expiry: (
                calls.append(("token", uses, expiry)) or "join-secret"),
            "announce": lambda config, access, room, replacement, token, deadline: (
                calls.append(("announce", room, replacement["domain"], token, deadline))
                or "message containing join-secret"),
        }
        result = self.rotation.run_once(
            self.state_path, now=100, deploy=deploy, retire=retired.append, api=api)
        self.assertEqual(result, "replacement announced")
        state = self.rotation._load_state(self.state_path)
        self.assertEqual(state["phase"], "grace")
        self.assertEqual(state["replacement"]["domain"], "matrix-2.example.test")
        self.assertTrue(state["replacement"]["matrix_registration_requires_token"])
        self.assertEqual(calls[0], ("token", 25, 3700))
        self.assertEqual(calls[1][3], "join-secret")
        self.assertNotIn("join-secret", json.dumps(state))
        self.assertEqual(
            self.rotation.run_once(
                self.state_path, now=3699, deploy=deploy,
                retire=retired.append, api=api),
            "grace window active")
        self.assertEqual(
            self.rotation.run_once(
                self.state_path, now=3700, deploy=deploy,
                retire=retired.append, api=api),
            "old deployment retired")
        state = self.rotation._load_state(self.state_path)
        self.assertEqual(state["phase"], "active")
        self.assertEqual(state["active"]["domain"], "matrix-2.example.test")
        self.assertEqual(retired, [self.active])
        self.assertEqual(len(deployed), 1)

    def test_failed_replacement_is_removed_and_active_server_is_kept(self):
        self.write_state(self.state())
        retired = []
        with self.assertRaisesRegex(self.rotation.RotationError, "deployment failed"):
            self.rotation.run_once(
                self.state_path, now=100, deploy=lambda config: False,
                retire=retired.append)
        state = self.rotation._load_state(self.state_path)
        self.assertEqual(state["phase"], "active")
        self.assertIsNone(state["replacement"])
        self.assertEqual(state["active"], self.active)
        self.assertEqual(retired, [])

    def test_cleanup_failure_preserves_recovery_state(self):
        self.write_state(self.state())

        def failed_cleanup(config):
            raise RuntimeError("provider unavailable")

        with self.assertRaisesRegex(self.rotation.RotationError, "state was preserved"):
            self.rotation.run_once(
                self.state_path, now=100, deploy=lambda config: True,
                retire=failed_cleanup,
                api={"login": mock.Mock(side_effect=RuntimeError("API unavailable"))})
        state = self.rotation._load_state(self.state_path)
        self.assertEqual(state["phase"], "provisioning")
        self.assertIsNotNone(state["replacement"])

    def test_interrupted_provisioning_is_recovered_before_new_work(self):
        state = self.state(phase="provisioning")
        state["replacement"] = dict(self.active, deployment_id="matrix-replacement")
        self.write_state(state)
        retired = []
        result = self.rotation.run_once(
            self.state_path, now=100, deploy=mock.Mock(), retire=retired.append)
        self.assertEqual(result, "recovered incomplete replacement")
        self.assertEqual(retired[0]["deployment_id"], "matrix-replacement")
        self.assertEqual(self.rotation._load_state(self.state_path)["phase"], "active")

    def test_synapse_template_requires_tokens_for_rotation_only(self):
        matrix_module = (
            ROOT / "ghost_protocol/phantom/modules/matrix.py").read_text()
        playbook = (
            ROOT / "ghost_protocol/phantom/playbooks/matrix/main.yml").read_text()
        template = (
            ROOT / "ghost_protocol/phantom/playbooks/matrix/templates/homeserver.yaml.j2"
        ).read_text()
        self.assertIn('matrix_registration_requires_token"] = False', matrix_module)
        self.assertIn("matrix_registration_token_required", playbook)
        self.assertIn("registration_requires_token:", template)


class TakBuilderTests(unittest.TestCase):
    def test_official_source_layout_uses_nested_gradle_wrapper(self):
        source = (ROOT / "scripts/build_tak_server.py").read_text()
        self.assertIn('build_root = source / "src"', source)
        self.assertIn('wrapper = build_root / "gradlew"', source)
        self.assertIn('cwd=build_root', source)

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
