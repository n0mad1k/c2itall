"""Focused offline Azure lifecycle and reviewed-smoke regression tests.

All cloud calls are mocked. Process timeout/signal tests use local sleeping
Python children; no Azure account, generated cloud resources or real SSH keys.
"""

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from utils import azure_utils as azure
from utils import cleanup_engine, deployment_engine, provider_utils
from utils import provider_registry as registry

spec = importlib.util.spec_from_file_location("azure_smoke", ROOT / "scripts/deploy_azure_smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class AzureFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.addCleanup(mock.patch.stopall)
        mock.patch.dict(os.environ, {"HOME": str(self.home)}).start()
        self.state_dir = self.home / "states"
        mock.patch.object(azure, "STATE_DIR", self.state_dir).start()
        self.key = self.home / ".ssh" / "c2deploy_test-azure"
        self.key.parent.mkdir()
        self.key.write_text("unit-test-private-key")
        Path(str(self.key) + ".pub").write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test")
        self.config = {
            "provider": "azure", "deployment_id": "test-azure",
            "deployment_type": "infrastructure", "infrastructure_deployment": True,
            "azure_subscription_id": smoke.SUBSCRIPTION, "azure_location": "eastus",
            "azure_vm_size": smoke.SIZE, "azure_resource_group": "c2itall-test-azure",
            "operator_ip": "8.8.8.8", "ssh_key_path": str(self.key) + ".pub",
            "ssh_private_key_path": str(self.key), "ssh_key_generated": False,
            "azure_state_dir": str(self.state_dir),
        }

    def prepare(self):
        return azure.prepare_state(self.config)

    def owned_state(self):
        self.config["ssh_key_generated"] = True
        public = Path(str(self.key) + ".pub")
        key_text, public_text = self.key.read_text(), public.read_text()
        self.key.unlink()
        public.unlink()
        state = self.prepare()
        self.key.write_text(key_text)
        public.write_text(public_text)
        return state

    def group(self, state):
        return {"id": f"/subscriptions/{smoke.SUBSCRIPTION}/resourceGroups/{state['azure_resource_group']}",
                "tags": azure.ownership_tags(state)}

    def resources(self, state):
        return [{"id": rid, "tags": azure.ownership_tags(state)}
                for rid in state["planned_resource_ids"].values()]


class ConfigurationTests(AzureFixture):
    def test_normalization_and_no_other_provider_secrets(self):
        result = azure.validate_config({**self.config, "aws_secret_key": "secret", "linode_token": "secret"})
        self.assertEqual(result["operator_ip"], "8.8.8.8/32")
        self.assertEqual(result["azure_os_disk_gb"], 32)
        self.assertNotIn("aws_secret_key", result)
        self.assertNotIn("linode_token", result)

    def test_invalid_configuration(self):
        for key, value in (("deployment_id", "../escape"), ("azure_subscription_id", "not-a-uuid"),
                           ("azure_resource_group", "group;command"), ("azure_location", "eastus --bad"),
                           ("azure_vm_size", "B1s"), ("operator_ip", "0.0.0.0/0"),
                           ("azure_os_disk_gb", 31), ("azure_os_disk_gb", True),
                           ("azure_os_disk_gb", "64"),
                           ("operator_ip", "8.8.8.0/24"), ("operator_ip", "127.0.0.1"),
                           ("operator_ip", "2001:4860:4860::8888"), ("ssh_key_generated", "true"),
                           ("deployment_type", "c2"), ("infrastructure_deployment", False)):
            with self.subTest(key=key, value=value), self.assertRaises((ValueError, KeyError)):
                azure.validate_config({**self.config, key: value})

    def test_generated_key_paths_must_be_exact_and_not_symlinks(self):
        self.config["ssh_key_generated"] = True
        with self.assertRaises(ValueError):
            azure.validate_config({**self.config, "ssh_private_key_path": str(self.key) + "-other"})
        self.key.unlink()
        self.key.symlink_to(self.home / "foreign-key")
        with self.assertRaises(ValueError):
            azure.validate_config(self.config)

    def test_public_key_validation(self):
        Path(self.config["ssh_key_path"]).write_text("not a public key\n")
        with self.assertRaises(ValueError):
            azure.validate_config(self.config)

    def test_cli_always_scopes_subscription_and_raises_on_bad_json(self):
        with mock.patch.object(azure, "run_command", return_value=subprocess.CompletedProcess([], 0, '{"ok":true}', "")) as command:
            self.assertEqual(azure.run_az(["group", "exists", "--name", "group"], smoke.SUBSCRIPTION), {"ok": True})
            self.assertIn(smoke.SUBSCRIPTION, command.call_args.args[0])
            self.assertIn("--subscription", command.call_args.args[0])
        with mock.patch.object(azure, "run_command", return_value=subprocess.CompletedProcess([], 0, "not JSON", "")):
            with self.assertRaises(json.JSONDecodeError):
                azure.run_az(["account", "show"], smoke.SUBSCRIPTION)


class StateAndCleanupTests(AzureFixture):
    def test_state_roundtrip_atomic_permissions_and_identity(self):
        state = self.prepare()
        path = self.state_dir / "test-azure.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(azure.load_state("test-azure"), state)
        self.assertEqual(azure.list_states(), [state])
        self.assertEqual(list(self.state_dir.glob("*.json")), [path])
        self.assertFalse(list(self.state_dir.glob(".test-azure.json*")))
        self.assertEqual(state["version"], 1)
        self.assertEqual(state["status"], "planned")
        self.assertEqual(len(state["planned_resource_ids"]), 6)
        self.assertEqual(self.prepare()["ownership_marker"], state["ownership_marker"])
        with self.assertRaises(ValueError):
            azure.prepare_state({**self.config, "azure_location": "westus"})

    def test_state_persists_before_key_creation(self):
        self.config["ssh_key_generated"] = True
        self.key.unlink()
        Path(str(self.key) + ".pub").unlink()
        state = self.prepare()
        self.assertEqual(azure.load_state(state["deployment_id"])["status"], "planned")

    def test_new_intent_cannot_claim_preexisting_keys(self):
        with self.assertRaises(ValueError):
            azure.prepare_state({**self.config, "ssh_key_generated": True})
        self.assertTrue(self.key.exists())

    def test_corrupt_state_cannot_change_resource_identity(self):
        state = self.prepare()
        state["planned_resource_ids"]["vm"] += "-foreign"
        azure.save_state(state)
        with self.assertRaises(ValueError):
            azure.load_state("test-azure")

    def test_fresh_process_recovers_before_legacy_logs_exist(self):
        self.prepare()
        script = (
            "import sys; from pathlib import Path; from unittest.mock import patch; "
            f"sys.path.insert(0, {str(ROOT)!r}); "
            "from utils import azure_utils as a, cleanup_engine as c; "
            f"a.STATE_DIR=Path({str(self.state_dir)!r}); "
            "p=patch.object(c,'execute_teardown',return_value=True); m=p.start(); "
            "assert c.teardown_by_deployment_id('test-azure'); "
            "assert m.call_count==1; assert m.call_args.args[0]['provider']=='azure'; "
            "assert m.call_args.args[0]['deployment_id']=='test-azure'"
        )
        result = subprocess.run([sys.executable, "-B", "-c", script], cwd=self.home,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertFalse((self.home / "logs").exists())

    def test_fresh_process_supported_recovery_cli(self):
        self.prepare()
        code = f'''import sys,runpy
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,{str(ROOT)!r})
from utils import azure_utils as a, cleanup_engine as c
a.STATE_DIR=Path({str(self.state_dir)!r})
sys.argv=['deploy_infrastructure.py','--teardown-id','test-azure']
with patch.object(c,'execute_teardown',return_value=True) as teardown:
    try:
        runpy.run_path({str(ROOT / 'modules/infrastructure/deploy_infrastructure.py')!r},run_name='__main__')
    except SystemExit as result:
        assert result.code==0, result.code
    teardown.assert_called_once()
    assert teardown.call_args.args[0]['deployment_id']=='test-azure'
'''
        result = subprocess.run([sys.executable, "-B", "-c", code], cwd=self.home,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_legacy_mixed_case_underscore_id_keeps_fallback(self):
        config = {"provider": "linode", "deployment_id": "Old_ID"}
        with mock.patch.object(cleanup_engine.glob, "glob", side_effect=[["legacy.log"], ["legacy.txt"]]), mock.patch.object(cleanup_engine, "parse_deployment_info", return_value=config), mock.patch.object(cleanup_engine, "execute_teardown", return_value=True) as cleanup, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(cleanup_engine.teardown_by_deployment_id("Old_ID"))
            cleanup.assert_called_once_with(config)

    def test_teardown_all_discovers_state_and_deduplicates_legacy_info(self):
        state = self.prepare()
        with mock.patch.object(cleanup_engine, "confirm_action", return_value=True), mock.patch.object(cleanup_engine.glob, "glob", return_value=["legacy.txt"]), mock.patch.object(cleanup_engine, "parse_deployment_info", return_value=state), mock.patch.object(cleanup_engine, "execute_teardown", return_value=True) as cleanup, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(cleanup_engine.teardown_all_infrastructure())
            cleanup.assert_called_once_with(state)

    def test_lifecycle_lock_blocks_fresh_cleanup_and_same_group_deployment(self):
        self.prepare()
        code = f'''import sys,json
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,{str(ROOT)!r})
from utils import azure_utils as a
config=json.loads({json.dumps(self.config)!r})
a.STATE_DIR=Path(config['azure_state_dir'])
with patch.object(a,'_group') as cloud:
    assert not a.cleanup_azure(config)
    cloud.assert_not_called()
    other=dict(config,deployment_id='other-deployment')
    assert not a.deploy_azure(other)
    cloud.assert_not_called()
'''
        with azure.lifecycle_lock(self.config):
            result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.state_dir / "test-azure.json").exists())

    def test_partial_deployment_failure_keeps_intent_and_key(self):
        with mock.patch.object(azure, "_group", return_value=None), mock.patch.object(deployment_engine, "execute_playbook", return_value=False):
            self.assertFalse(azure.deploy_azure(self.config))
        state = azure.load_state("test-azure")
        self.assertEqual(state["status"], "failed")
        self.assertTrue(state["planned_resource_ids"])
        self.assertTrue(self.key.exists())

    def test_wrong_subscription_is_refused_before_cloud_calls(self):
        self.prepare()
        with mock.patch.object(azure, "run_az") as cloud, mock.patch.object(deployment_engine, "execute_playbook") as mutate:
            self.assertFalse(azure.cleanup_azure({**self.config, "azure_subscription_id": "00000000-0000-0000-0000-000000000000"}))
            cloud.assert_not_called()
            mutate.assert_not_called()
        self.assertTrue(self.key.exists())

    def test_foreign_group_and_unexpected_resources_refuse_deletion(self):
        state = self.prepare()
        scenarios = [
            ({**self.group(state), "tags": {}}, []),
            (self.group(state), [{"id": state["planned_resource_ids"]["vm"] + "-foreign", "tags": azure.ownership_tags(state)}]),
            (self.group(state), [{"id": state["planned_resource_ids"]["vm"], "tags": {}}]),
        ]
        for group, resources in scenarios:
            with self.subTest(group=group, resources=resources), mock.patch.object(azure, "_group", return_value=group), mock.patch.object(azure, "_resources", return_value=resources), mock.patch.object(deployment_engine, "execute_playbook") as mutate:
                self.assertFalse(azure.cleanup_azure(self.config))
                mutate.assert_not_called()
                self.assertTrue(self.key.exists())
                self.assertTrue((self.state_dir / "test-azure.json").exists())

    def test_implicit_os_disk_requires_exact_owned_vm(self):
        state = self.prepare()
        disk = {"id": state["planned_resource_ids"]["os_disk"], "managedBy": state["planned_resource_ids"]["vm"]}
        azure.validate_ownership(state, self.group(state), [disk])
        with self.assertRaises(ValueError):
            azure.validate_ownership(state, self.group(state), [{**disk, "managedBy": disk["managedBy"] + "-foreign"}])

    def test_cleanup_removes_only_exact_generated_keys_after_absence(self):
        self.owned_state()
        neighbor = Path(str(self.key) + "-keep")
        neighbor.write_text("unrelated")
        with mock.patch.object(azure, "_group", return_value=None):
            self.assertTrue(azure.cleanup_azure(self.config))
        self.assertFalse(self.key.exists())
        self.assertFalse(Path(str(self.key) + ".pub").exists())
        self.assertTrue(neighbor.exists())
        self.assertFalse((self.state_dir / "test-azure.json").exists())
        self.assertEqual(json.loads((self.state_dir / "archive/test-azure.json").read_text())["status"], "deleted")

    def test_user_supplied_keys_are_preserved(self):
        self.config["ssh_key_generated"] = False
        self.prepare()
        with mock.patch.object(azure, "_group", return_value=None):
            self.assertTrue(azure.cleanup_azure(self.config))
        self.assertTrue(self.key.exists())
        self.assertTrue(Path(str(self.key) + ".pub").exists())

    def test_deletion_failure_preserves_state_and_key(self):
        state = self.owned_state()
        with mock.patch.object(azure, "_group", return_value=self.group(state)), mock.patch.object(azure, "_resources", return_value=self.resources(state)), mock.patch.object(azure, "_wait_deployment") as cancel, mock.patch.object(deployment_engine, "execute_playbook", return_value=False):
            self.assertFalse(azure.cleanup_azure(self.config))
            self.assertTrue(cancel.call_args.kwargs["cancel"])
        self.assertEqual(azure.load_state("test-azure")["status"], "cleanup_failed")
        self.assertTrue(self.key.exists())

    def test_deletion_wait_timeout_is_not_success(self):
        state = self.owned_state()
        with mock.patch.object(azure, "_group", return_value=self.group(state)), mock.patch.object(azure, "_resources", return_value=self.resources(state)), mock.patch.object(azure, "_wait_deployment"), mock.patch.object(deployment_engine, "execute_playbook", return_value=True):
            self.assertFalse(azure.cleanup_azure({**self.config, "azure_cleanup_deadline": time.monotonic() - 1}))
        self.assertTrue(self.key.exists())
        self.assertTrue((self.state_dir / "test-azure.json").exists())


class RoutingAndTemplateTests(AzureFixture):
    def test_old_provider_selection_and_azure_capability(self):
        with mock.patch("builtins.input", return_value="1"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(provider_utils.select_provider(), "aws")
            self.assertEqual(provider_utils.select_provider("infrastructure"), "azure")
        with mock.patch("builtins.input", return_value="3"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(provider_utils.select_provider(), "flokinet")

    def test_deferred_workloads_offer_new_routes_and_explicit_legacy_fallbacks(self):
        self.assertEqual(
            provider_utils.available_providers('c2', legacy_fallback=True),
            ['aws', 'linode', 'flokinet'])
        azure_spec = registry.PROVIDER_SPECS['azure']._replace(
            routes=dict(registry.PROVIDER_SPECS['azure'].routes, c2='fake:Adapter'))
        with mock.patch.dict(registry.PROVIDER_SPECS, {'azure': azure_spec}):
            self.assertEqual(
                provider_utils.available_providers('c2', legacy_fallback=True),
                ['aws', 'linode', 'flokinet', 'azure'])

    def test_workload_config_prefers_registered_handler_then_legacy_loader(self):
        adapter = mock.Mock()
        adapter.gather_config.return_value = {'source': 'new'}
        factory = mock.Mock(return_value=adapter)
        azure_spec = registry.PROVIDER_SPECS['azure']._replace(
            routes=dict(registry.PROVIDER_SPECS['azure'].routes, c2='fake:Adapter'))
        with mock.patch.dict(registry.PROVIDER_SPECS, {'azure': azure_spec}), mock.patch.object(registry, '_load', return_value=factory):
            self.assertEqual(
                provider_utils.gather_provider_config(
                    'azure', 'c2', legacy_fallback=True),
                {'source': 'new'})
            adapter.gather_config.assert_called_once_with()

        from utils import aws_utils
        with mock.patch.object(
                aws_utils, 'gather_aws_config', return_value={'source': 'transition'}) as loader:
            self.assertEqual(
                provider_utils.gather_provider_config(
                    'aws', 'c2', legacy_fallback=True),
                {'source': 'transition'})
            loader.assert_called_once_with()

        with self.assertRaisesRegex(ValueError, 'No configuration route'):
            provider_utils.gather_provider_config('azure', 'c2', legacy_fallback=True)

    def test_canonical_workload_dispatch_never_retries_failed_handler(self):
        config = {'provider': 'azure', 'provider_workload': 'phishing',
                  'deployment_type': 'gophish_only'}
        self.assertEqual(registry.requested_workload(config), 'phishing')
        adapter = mock.Mock()
        legacy = mock.Mock(return_value=True)
        adapter.deploy.return_value = True
        with mock.patch.object(deployment_engine, 'workload_route', return_value=adapter):
            self.assertTrue(deployment_engine.dispatch_workload(config, legacy))
        adapter.deploy.assert_called_once_with(config)
        legacy.assert_not_called()

        adapter.deploy.side_effect = RuntimeError('handler failed')
        with mock.patch.object(deployment_engine, 'workload_route', return_value=adapter), self.assertRaisesRegex(RuntimeError, 'handler failed'):
            deployment_engine.dispatch_workload(config, legacy)
        legacy.assert_not_called()

        with mock.patch.object(deployment_engine, 'workload_route', return_value=None):
            self.assertFalse(deployment_engine.dispatch_workload(config, legacy))
        legacy.assert_not_called()

        legacy_config = dict(config, provider='aws')
        with mock.patch.object(deployment_engine, 'workload_route', return_value=None):
            self.assertTrue(
                deployment_engine.dispatch_workload(legacy_config, legacy))
        legacy.assert_called_once_with(legacy_config)

    def test_deferred_module_menus_request_canonical_workload_with_fallback(self):
        cases = (
            ('modules/attack-box/deploy_attack_box.py', 'gather_attack_box_parameters', 'attack_box'),
            ('modules/c2/deploy_c2.py', 'gather_c2_parameters', 'c2'),
            ('modules/redirectors/deploy_redirector.py', 'gather_redirector_parameters', 'redirector'),
            ('modules/phishing/deploy_phishing.py', 'gather_phishing_parameters', 'phishing'),
            ('modules/payload-server/deploy_payload.py', 'gather_payload_parameters', 'payload_server'),
        )
        for index, (relative_path, function_name, workload) in enumerate(cases):
            with self.subTest(workload=workload):
                module_spec = importlib.util.spec_from_file_location(
                    f'deferred_module_{index}', ROOT / relative_path)
                module = importlib.util.module_from_spec(module_spec)
                module_spec.loader.exec_module(module)
                with mock.patch.object(module, 'clear_screen'), mock.patch.object(module, 'print_banner'), mock.patch.object(module, 'generate_deployment_id', return_value='test-id'), mock.patch.object(module, 'select_provider', return_value='aws') as select, mock.patch.object(module, 'gather_provider_config', return_value=None) as gather, contextlib.redirect_stdout(io.StringIO()):
                    self.assertIsNone(getattr(module, function_name)())
                select.assert_called_once_with(workload, legacy_fallback=True)
                gather.assert_called_once_with(
                    'aws', workload, legacy_fallback=True)

    def test_direct_legacy_modules_enter_dispatcher_before_existing_executor(self):
        cases = (
            ('modules/phishing/deploy_phishing.py', 'execute_phishing_deployment',
             'execute_component_deployment', {
                 'provider': 'aws', 'provider_workload': 'phishing',
                 'deployment_type': 'gophish_only', 'deployment_id': 'test-id',
                 'phishing_domain': 'example.test'}),
            ('modules/payload-server/deploy_payload.py', 'execute_payload_deployment',
             'execute_ansible_deployment', {
                 'provider': 'aws', 'provider_workload': 'payload_server',
                 'deployment_type': 'basic_payload_server',
                 'deployment_id': 'test-id', 'domain': 'example.test'}),
        )
        for index, (relative_path, function_name, legacy_name, config) in enumerate(cases):
            with self.subTest(workload=config['provider_workload']):
                module_spec = importlib.util.spec_from_file_location(
                    f'direct_module_{index}', ROOT / relative_path)
                module = importlib.util.module_from_spec(module_spec)
                module_spec.loader.exec_module(module)
                with mock.patch.object(module, 'clear_screen'), mock.patch.object(module, 'print_banner'), mock.patch.object(module, 'setup_logging'), mock.patch.object(module, 'confirm_action', return_value=True), mock.patch.object(module, 'wait_for_input'), mock.patch.object(module, 'archive_old_logs', create=True), mock.patch.object(deployment_engine, 'dispatch_workload', return_value=False) as dispatch, contextlib.redirect_stdout(io.StringIO()):
                    getattr(module, function_name)(config)
                dispatch.assert_called_once_with(config, getattr(module, legacy_name))

    def test_composite_dispatch_uses_one_lifecycle_and_refuses_partial_fallback(self):
        config = {'providers': ['linode', 'aws'],
                  'provider_workload': 'webrunner'}
        legacy = mock.Mock(return_value=True)
        with mock.patch.object(
                deployment_engine, 'composite_workload_routes',
                return_value=[('linode', None), ('aws', None)]):
            self.assertTrue(
                deployment_engine.dispatch_composite_workload(config, legacy))
        legacy.assert_called_once_with(config)

        adapter = mock.Mock()
        adapter.deploy.return_value = True
        with mock.patch.object(
                deployment_engine, 'composite_workload_routes',
                return_value=[('azure', adapter)]):
            self.assertTrue(
                deployment_engine.dispatch_composite_workload(config, legacy))
        adapter.deploy.assert_called_once_with(config)
        legacy.assert_called_once()

        adapter.deploy.side_effect = RuntimeError('composite handler failed')
        with mock.patch.object(
                deployment_engine, 'composite_workload_routes',
                return_value=[('azure', adapter)]), self.assertRaisesRegex(
                    RuntimeError, 'composite handler failed'):
            deployment_engine.dispatch_composite_workload(config, legacy)
        legacy.assert_called_once()

        for routes in (
                [('linode', None), ('azure', adapter)],
                [('azure', mock.Mock()), ('other', object())]):
            with self.subTest(routes=routes), mock.patch.object(
                    deployment_engine, 'composite_workload_routes',
                    return_value=routes):
                self.assertFalse(
                    deployment_engine.dispatch_composite_workload(config, legacy))
        legacy.assert_called_once()

    def test_composite_route_validation(self):
        for providers in (None, [], ['aws', 'aws'], ['aws', '']):
            with self.subTest(providers=providers), self.assertRaises(ValueError):
                registry.composite_workload_routes({
                    'providers': providers, 'provider_workload': 'webrunner'})
        routes = registry.composite_workload_routes({
            'providers': ['linode', 'aws'],
            'provider_workload': 'webrunner'})
        self.assertEqual([provider for provider, _ in routes], ['linode', 'aws'])
        self.assertEqual([adapter.provider for _, adapter in routes], ['linode', 'aws'])
        self.assertEqual(len({type(adapter) for _, adapter in routes}), 1)

    def test_non_phantom_transition_routes_call_preserved_executor_once(self):
        from utils.legacy_provider_adapter import LegacyProviderAdapter
        expected = {
            'aws': {'attack_box', 'c2', 'payload_server', 'phishing',
                    'redirector', 'webrunner'},
            'linode': {'attack_box', 'c2', 'payload_server', 'phishing',
                       'redirector', 'webrunner'},
            'flokinet': {'c2', 'payload_server', 'phishing', 'redirector',
                         'webrunner'},
        }
        for provider, workloads in expected.items():
            with self.subTest(provider=provider):
                self.assertTrue(workloads.issubset(
                    registry.PROVIDER_SPECS[provider].capabilities))
                for workload in workloads:
                    adapter = registry.provider_dispatcher(provider).route(workload)
                    self.assertIsInstance(adapter, LegacyProviderAdapter)
                    self.assertEqual(adapter.provider, provider)

        config = {'provider': 'aws', 'provider_workload': 'c2',
                  'deployment_id': 'transition-test'}
        legacy = mock.Mock(return_value=False)
        self.assertFalse(deployment_engine.dispatch_workload(config, legacy))
        legacy.assert_called_once_with(config)
        legacy.reset_mock(side_effect=True)
        legacy.side_effect = RuntimeError('preserved executor failed')
        with self.assertRaisesRegex(RuntimeError, 'preserved executor failed'):
            deployment_engine.dispatch_workload(config, legacy)
        legacy.assert_called_once_with(config)

        with mock.patch.object(
                cleanup_engine, 'execute_legacy_teardown', return_value=True) as cleanup:
            self.assertTrue(registry.workload_route(config).cleanup(config))
        cleanup.assert_called_once_with(config)

    def test_legacy_lifecycle_artifacts_are_owner_only_and_hide_teardown_secrets(self):
        logs = self.home / 'logs'
        logs.mkdir()
        config = {
            'provider': 'aws', 'provider_workload': 'c2',
            'deployment_id': 'secure-lifecycle', 'deployment_type': 'c2',
            'aws_access_key': 'access', 'aws_secret_key': 'secret',
        }
        previous = Path.cwd()
        try:
            os.chdir(self.home)
            deployment_engine.save_deployment_info(config)
        finally:
            os.chdir(previous)
        info = logs / 'deployment_info_secure-lifecycle.txt'
        self.assertEqual(info.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('secret', info.read_text())

        captured = {}

        def run(argv, **kwargs):
            variables = argv[argv.index('--extra-vars') + 1]
            self.assertTrue(variables.startswith('@'))
            path = Path(variables[1:])
            captured['path'] = path
            captured['mode'] = path.stat().st_mode & 0o777
            captured['data'] = json.loads(path.read_text())
            self.assertNotIn('secret', ' '.join(argv))
            return subprocess.CompletedProcess(argv, 0, '', '')

        with mock.patch.object(cleanup_engine.subprocess, 'run', side_effect=run):
            self.assertTrue(cleanup_engine.run_teardown_playbook('cleanup.yml', config))
        self.assertEqual(captured['mode'], 0o600)
        self.assertEqual(captured['data']['aws_secret_key'], 'secret')
        self.assertFalse(captured['path'].exists())

    def test_saved_workload_reenters_dispatcher_after_restart(self):
        from utils.legacy_provider_adapter import LegacyProviderAdapter

        logs = self.home / 'logs'
        logs.mkdir()
        config = {
            'provider': 'aws', 'provider_workload': 'c2',
            'deployment_id': 'restart-route',
            # The subtype is deliberately not a registered workload. Cleanup
            # must use the canonical workload persisted alongside it.
            'deployment_type': 'cobalt_strike',
        }
        previous = Path.cwd()
        try:
            os.chdir(self.home)
            deployment_engine.save_deployment_info(config)
            restored = cleanup_engine.parse_deployment_info(
                'logs/deployment_info_restart-route.txt')
        finally:
            os.chdir(previous)

        self.assertEqual(restored['provider_workload'], 'c2')
        self.assertIsInstance(registry.workload_route(restored), LegacyProviderAdapter)
        with mock.patch.object(
                cleanup_engine, 'execute_legacy_teardown', return_value=True) as legacy:
            self.assertTrue(cleanup_engine.execute_teardown(restored))
        legacy.assert_called_once_with(restored)

    def test_webrunner_uses_registry_order_and_composite_dispatch(self):
        module_spec = importlib.util.spec_from_file_location(
            'webrunner_dispatch_test',
            ROOT / 'modules/webrunner/deploy_webrunner.py')
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        with mock.patch.object(
                module, 'available_providers',
                return_value=['aws', 'azure', 'linode', 'flokinet']), mock.patch(
                    'builtins.input', return_value='1'), contextlib.redirect_stdout(
                        io.StringIO()):
            self.assertEqual(module._select_providers(), ['linode'])
        with mock.patch.object(
                module, 'available_providers',
                return_value=['aws', 'azure', 'linode', 'flokinet']), mock.patch(
                    'builtins.input', return_value='4'), contextlib.redirect_stdout(
                        io.StringIO()):
            self.assertEqual(module._select_providers(), ['azure'])

        with mock.patch.object(module, 'clear_screen'), mock.patch.object(
                module, 'print_banner'), mock.patch.object(
                    module, 'generate_deployment_id', return_value='test-id'), mock.patch.object(
                        module, '_select_providers', return_value=['linode']), mock.patch.object(
                            module, 'gather_provider_config', return_value=None) as gather, mock.patch(
                                'builtins.input', side_effect=['', '']), contextlib.redirect_stdout(
                                    io.StringIO()):
            self.assertIsNone(module.gather_webrunner_parameters())
        gather.assert_called_once_with(
            'linode', 'webrunner', legacy_fallback=True)

        config = {
            'deployment_id': 'test-id', 'webrunner_name': 'wr-test-id',
            'engagement': 'test-id', 'providers': ['linode'],
            'provider_workload': 'webrunner', 'preset': 'balanced',
            'chunk_size': 1000, 'scan_mode': 'nmap-only', 'ports': [443],
            'masscan_rate': 100, 'total_ips': 1, 'use_tor': False,
            'enhanced_opsec': False, 'teardown_after_scan': True,
            'country_codes': [], 'node_chunks': [{
                'provider': 'linode', 'node_name': 'wr-test-id-01',
                'cidrs': ['192.0.2.1/32'], 'ip_count': 1, 'idx': 0,
                'region': 'us-east'}],
        }
        with mock.patch.object(module, '_base', self.temporary.name), mock.patch.object(
                module, 'clear_screen'), mock.patch.object(module, 'print_banner'), mock.patch.object(
                    module, 'setup_logging'), mock.patch.object(
                        module, 'confirm_action', return_value=True), mock.patch.object(
                            module, 'wait_for_input'), mock.patch.object(
                                module, 'dispatch_composite_workload', return_value=False) as dispatch, contextlib.redirect_stdout(
                                    io.StringIO()):
            module.execute_webrunner_deployment(config)
        dispatch.assert_called_once_with(config, module._execute_webrunner_legacy)

    def test_existing_routes_remain_and_azure_cannot_route_payloads(self):
        for provider, dirname in (("aws", "AWS"), ("linode", "Linode"), ("flokinet", "FlokiNET")):
            self.assertEqual(deployment_engine.determine_playbook({"provider": provider, "c2_only": True}), f"providers/{dirname}/c2.yml")
            self.assertEqual(deployment_engine.determine_playbook({"provider": provider, "attack_box_deployment": True}), f"providers/{dirname}/attack_box.yml")
        self.assertTrue(deployment_engine.determine_playbook(self.config).endswith("providers/Azure/infrastructure.yml"))
        for extra in ({"c2_only": True}, {"attack_box_deployment": True}, {"phishing_deployment": True}, {"infrastructure_deployment": False}):
            self.assertIsNone(deployment_engine.determine_playbook({**self.config, **extra}))

    def test_phantom_route_is_advertised_without_exposing_other_azure_workloads(self):
        self.assertEqual(
            provider_utils.available_providers('phantom', legacy_fallback=True),
            ['aws', 'linode', 'flokinet', 'azure'])
        self.assertEqual(
            provider_utils.available_providers('c2', legacy_fallback=True),
            ['aws', 'linode', 'flokinet'])
        self.assertEqual(
            provider_utils.available_providers('chat', legacy_fallback=True),
            ['aws', 'linode', 'flokinet', 'azure'])
        from utils.azure_phantom_adapter import _service_rules
        self.assertEqual(
            {(rule['protocol'], rule['port']) for rule in _service_rules({
                'server_type': 'matrix', 'provider_workload': 'chat'})},
            {('Tcp', 80), ('Tcp', 443), ('Tcp', 8448), ('Udp', 41641)})
        self.assertEqual(
            {(rule['protocol'], rule['port']) for rule in _service_rules({
                'server_type': 'tak', 'provider_workload': 'chat'})},
            {('Tcp', 8089), ('Tcp', 8443), ('Tcp', 8446), ('Udp', 41641)})

    def test_deferred_chat_module_uses_shared_provider_route_and_phantom(self):
        module_spec = importlib.util.spec_from_file_location(
            'deferred_chat_module', ROOT / 'modules/chat-server/deploy_chat.py')
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        matrix = mock.Mock()
        matrix.gather_config.side_effect = lambda config: dict(config, domain='matrix.test')
        with mock.patch.object(module, 'clear_screen'), mock.patch.object(
                module, 'print_banner'), mock.patch.object(
                    module, 'select_provider', return_value='azure') as select, mock.patch.object(
                        module, 'gather_provider_config', return_value={'azure_location': 'eastus'}) as gather, mock.patch.object(
                            module, 'generate_deployment_id', return_value='chat-test'), mock.patch.object(
                                module, '_load_matrix_config', return_value=matrix), mock.patch.object(
                                    module.getpass, 'getpass', return_value=''), mock.patch(
                                        'builtins.input', return_value='n'):
            config = module.gather_chat_parameters()
        select.assert_called_once_with('chat', legacy_fallback=True)
        gather.assert_called_once_with('azure', 'chat', legacy_fallback=True)
        self.assertEqual(config['provider_workload'], 'chat')
        self.assertEqual(config['domain'], 'matrix.test')

        phantom = mock.Mock()
        phantom.deploy.return_value = True
        phantom.run_playbook.return_value = True
        with mock.patch.object(module, '_load_phantom', return_value=phantom):
            self.assertTrue(module.deploy_chat(config))
        phantom.deploy.assert_called_once_with('matrix', config)
        phantom.run_playbook.assert_called_once_with(module.ADDONS_PLAYBOOK, config)
        phantom.save_deploy_info.assert_called_once_with(config)

    def test_azure_phantom_adapter_limits_service_ports_and_maps_outputs(self):
        from utils.azure_phantom_adapter import AzurePhantomAdapter
        adapter = AzurePhantomAdapter()
        config = {
            'provider': 'azure', 'provider_workload': 'phantom',
            'deployment_id': 'test-azure', 'server_type': 'vpn',
            'vpn_port': '51820', 'azure_subscription_id': smoke.SUBSCRIPTION,
            'azure_location': 'eastus', 'azure_vm_size': smoke.SIZE,
            'operator_ip': '8.8.8.8', 'azure_state_dir': str(self.state_dir),
        }
        infrastructure = adapter._infrastructure_config(config)
        normalized = azure.validate_config(infrastructure)
        self.assertEqual(normalized['azure_inbound_rules'], [{
            'name': 'wireguard', 'protocol': 'Udp', 'port': '51820',
            'source': '*'}])
        rules = azure.render_template(infrastructure)['resources'][0][
            'properties']['securityRules']
        self.assertEqual(
            [(rule['properties']['protocol'],
              rule['properties']['destinationPortRange']) for rule in rules],
            [('Tcp', '22'), ('Udp', '51820'), ('*', '*')])
        self.assertEqual(rules[0]['properties']['sourceAddressPrefix'], '8.8.8.8/32')

        state = dict(normalized, outputs={
            'public_ip': {'value': '1.1.1.1'}}, status='ready')
        with mock.patch.object(azure, 'prepare_state'), mock.patch.object(
                azure, 'prepare_ssh_key'), mock.patch.object(
                    azure, 'deploy_azure', return_value=True), mock.patch.object(
                        azure, 'load_state', return_value=state):
            self.assertTrue(adapter.deploy(config))
        self.assertEqual(config['target_host'], '1.1.1.1')
        self.assertEqual(config['ssh_user'], 'azureuser')
        self.assertEqual(config['ssh_key'], str(self.key))
        self.assertEqual(config['provider_workload'], 'phantom')

        chat_config = dict(config, deployment_id='test-chat',
                           provider_workload='chat', server_type='tak')
        chat_config.pop('azure_os_disk_gb', None)
        chat_infrastructure = adapter._infrastructure_config(chat_config)
        self.assertEqual(chat_infrastructure['azure_os_disk_gb'], 64)
        with mock.patch.object(azure, 'prepare_state'), mock.patch.object(
                azure, 'prepare_ssh_key'), mock.patch.object(
                    azure, 'deploy_azure', return_value=True), mock.patch.object(
                        azure, 'load_state', return_value=dict(
                            chat_infrastructure, outputs={
                                'public_ip': {'value': '1.1.1.1'}}, status='ready')):
            self.assertTrue(adapter.deploy(chat_config))
        self.assertEqual(chat_config['provider_workload'], 'chat')

        with mock.patch.object(azure, 'cleanup_azure', return_value=True) as cleanup:
            self.assertTrue(adapter.cleanup(config))
        cleanup.assert_called_once_with({
            'deployment_id': 'test-azure',
            'azure_state_dir': str(self.state_dir),
            'azure_subscription_id': smoke.SUBSCRIPTION,
            'azure_resource_group': 'c2itall-test-azure',
        })

    def test_azure_phantom_adapter_maps_every_supported_service_allowlist(self):
        from utils.azure_phantom_adapter import _service_rules
        expected = {
            'vpn': {('Udp', 51820)},
            'dns': {('Tcp', 53), ('Udp', 53), ('Tcp', 80), ('Tcp', 443)},
            'matrix': {('Tcp', 80), ('Tcp', 443), ('Tcp', 8448)},
            'email': {('Tcp', 80), ('Tcp', 443), ('Tcp', 25), ('Tcp', 465),
                      ('Tcp', 587), ('Tcp', 993), ('Tcp', 4190), ('Tcp', 53),
                      ('Udp', 53)},
            'cloud': {('Tcp', 80), ('Tcp', 443)},
            'vault': {('Tcp', 80), ('Tcp', 443)},
            'media': {('Tcp', 80), ('Tcp', 443)},
            'all_in_one': {('Tcp', 80), ('Tcp', 443)},
            'tak': {('Tcp', 8089), ('Tcp', 8443), ('Tcp', 8446), ('Udp', 41641)},
        }
        for service, ports in expected.items():
            with self.subTest(service=service):
                rules = _service_rules({'server_type': service})
                self.assertEqual({(rule['protocol'], rule['port']) for rule in rules},
                                 ports)
                self.assertTrue(all(rule['source'] == '*' for rule in rules))
        with self.assertRaises(ValueError):
            _service_rules({'server_type': 'unsupported'})

    def test_azure_inbound_rules_reject_unsafe_or_ambiguous_values(self):
        invalid = (
            'not-a-list',
            [{'name': 'bad', 'protocol': 'Icmp', 'port': 80, 'source': '*'}],
            [{'name': 'ssh', 'protocol': 'Tcp', 'port': 22, 'source': '*'}],
            [{'name': 'web', 'protocol': 'Tcp', 'port': 80, 'source': '0.0.0.0/0'}],
            [{'name': 'web', 'protocol': 'Tcp', 'port': 80, 'source': '*'},
             {'name': 'web-2', 'protocol': 'tcp', 'port': '80', 'source': '*'}],
        )
        for rules in invalid:
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                azure.validate_config({**self.config, 'azure_inbound_rules': rules})

    def test_shared_entry_points_dispatch_to_azure(self):
        with mock.patch.object(azure, "deploy_azure", return_value=True) as deploy:
            self.assertTrue(deployment_engine.deploy_infrastructure(self.config))
            deploy.assert_called_once()
        with mock.patch.object(azure, "cleanup_azure", return_value=True) as cleanup:
            self.assertTrue(cleanup_engine.execute_teardown(self.config))
            cleanup.assert_called_once()

    def test_rendered_arm_security_and_determinism(self):
        state = self.prepare()
        template = azure.render_template(state)
        self.assertEqual(template, azure.render_template(state))
        resources = template["resources"]
        types = {resource["type"]: resource for resource in resources}
        self.assertNotIn("Microsoft.Storage/storageAccounts", types)
        vm = types["Microsoft.Compute/virtualMachines"]
        self.assertEqual(vm["apiVersion"], "2024-11-01")
        self.assertTrue(vm["properties"]["osProfile"]["linuxConfiguration"]["disablePasswordAuthentication"])
        self.assertTrue(vm["properties"]["diagnosticsProfile"]["bootDiagnostics"]["enabled"])
        self.assertNotIn("storageUri", vm["properties"]["diagnosticsProfile"]["bootDiagnostics"])
        self.assertEqual(vm["properties"]["storageProfile"]["osDisk"]["diskSizeGB"], 32)
        self.assertEqual(vm["properties"]["storageProfile"]["osDisk"]["managedDisk"]["storageAccountType"], "StandardSSD_LRS")
        larger = azure.prepare_state({**self.config, "deployment_id": "larger-disk",
                                      "azure_resource_group": "c2itall-larger-disk",
                                      "azure_os_disk_gb": 64})
        larger_vm = next(resource for resource in azure.render_template(larger)["resources"]
                         if resource["type"] == "Microsoft.Compute/virtualMachines")
        self.assertEqual(
            larger_vm["properties"]["storageProfile"]["osDisk"]["diskSizeGB"], 64)
        rules = types["Microsoft.Network/networkSecurityGroups"]["properties"]["securityRules"]
        allows = [rule["properties"] for rule in rules if rule["properties"]["access"] == "Allow"]
        self.assertEqual(len(allows), 1)
        self.assertEqual(allows[0]["sourceAddressPrefix"], "8.8.8.8/32")
        self.assertEqual(allows[0]["destinationPortRange"], "22")
        self.assertTrue(any(rule["properties"]["access"] == "Deny" and rule["properties"]["destinationPortRange"] == "*" for rule in rules))
        self.assertNotIn("customData", vm["properties"]["osProfile"])
        for resource in resources:
            self.assertEqual(resource["tags"], azure.ownership_tags(state))
            if resource["type"].startswith("Microsoft.Network/"):
                self.assertEqual(resource["apiVersion"], "2024-05-01")
        self.assertEqual(vm["name"], state["planned_resource_ids"]["vm"].rsplit("/", 1)[1])

    def test_populated_unrelated_credentials_are_excluded_from_child_and_vars(self):
        secrets = {"AWS_ACCESS_KEY_ID": "aws-key", "AWS_SECRET_ACCESS_KEY": "aws-secret", "AWS_SESSION_TOKEN": "aws-session", "LINODE_TOKEN": "linode-secret", "FLOKINET_API_KEY": "floki-secret", "ANSIBLE_EXTRA_VARS": "leaked"}
        state = self.prepare()
        config = {**state, "azure_state_dir": str(self.state_dir), "aws_secret_key": "aws-secret", "linode_token": "linode-secret", "flokinet_api_key": "floki-secret"}
        captured = {}
        def execute(argv, **kwargs):
            captured["variables"] = json.loads(Path(argv[argv.index("--extra-vars") + 1][1:]).read_text())
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch.dict(os.environ, secrets), mock.patch.object(azure, "run_command", side_effect=execute) as command:
            env = azure.azure_environment()
            self.assertFalse(set(secrets) & set(env))
            self.assertFalse(set(secrets) & set(smoke.child_environment()))
            self.assertTrue(deployment_engine.execute_playbook(str(ROOT / "providers/Azure/infrastructure.yml"), config))
            command.assert_called_once()
            argv = command.call_args.args[0]
            serialized = json.dumps(argv)
            for secret in secrets.values():
                self.assertNotIn(secret, serialized)
                self.assertNotIn(secret, json.dumps(captured["variables"]))
            self.assertEqual(os.environ["AWS_SECRET_ACCESS_KEY"], "aws-secret")


class ProviderContractTests(AzureFixture):
    def test_health_reads_owned_vm_without_mutating_state(self):
        state = self.prepare()
        before = (self.state_dir / 'test-azure.json').read_bytes()
        view = {'id': state['planned_resource_ids']['vm'], 'statuses': [
            {'code': 'ProvisioningState/succeeded'}, {'code': 'PowerState/running'}]}
        with mock.patch.object(azure, '_group', return_value=self.group(state)), mock.patch.object(azure, '_resources', return_value=self.resources(state)), mock.patch.object(azure, 'run_az', return_value=view) as cli:
            result = registry.infrastructure_adapter('azure').health(self.config)
            self.assertTrue(result['healthy'])
            self.assertEqual(cli.call_args.args[0][:2], ['vm', 'get-instance-view'])
            self.assertEqual(cli.call_args.args[1], smoke.SUBSCRIPTION)
        self.assertEqual((self.state_dir / 'test-azure.json').read_bytes(), before)

    def test_health_missing_stopped_or_unknown_vm_is_not_success(self):
        state = self.prepare()
        with mock.patch.object(azure, '_group', return_value=None), mock.patch.object(azure, 'run_az') as cli:
            self.assertFalse(azure.health_azure(self.config)['healthy'])
            cli.assert_not_called()
        for statuses in ([], [{'code': 'PowerState/deallocated'}], [{'code': 'PowerState/running'}],
                         [{'code': 'PowerState/running'}, {'code': 'PowerState/deallocated'}, {'code': 'ProvisioningState/succeeded'}]):
            view = {'id': state['planned_resource_ids']['vm'], 'statuses': statuses}
            with mock.patch.object(azure, '_group', return_value=self.group(state)), mock.patch.object(azure, '_resources', return_value=self.resources(state)), mock.patch.object(azure, 'run_az', return_value=view):
                self.assertFalse(azure.health_azure(self.config)['healthy'])

    def test_health_refuses_wrong_subscription_and_foreign_response(self):
        state = self.prepare()
        with mock.patch.object(azure, '_group') as group, self.assertRaisesRegex(ValueError, 'identity'):
            azure.health_azure({**self.config, 'azure_subscription_id': 'wrong'})
        group.assert_not_called()
        with mock.patch.object(azure, '_group', return_value=self.group(state)), mock.patch.object(azure, '_resources', return_value=self.resources(state)), mock.patch.object(azure, 'run_az', return_value={'id': '/foreign'}), self.assertRaisesRegex(ValueError, 'owned VM'):
            azure.health_azure(self.config)

    def test_health_collection_reports_errors_and_unsupported_checks(self):
        state = self.prepare()
        for error in (RuntimeError('API unavailable'), NotImplementedError()):
            adapter = mock.Mock()
            adapter.health.side_effect = error
            with mock.patch.object(registry, 'list_infrastructure_states', return_value=[state]), mock.patch.object(registry, 'infrastructure_adapter', return_value=adapter):
                report = registry.infrastructure_health()[0]
                self.assertFalse(report['healthy'])
                self.assertEqual(report['deployment_id'], state['deployment_id'])

    def test_standalone_teardown_prefers_adapter_state_without_legacy_key_cleanup(self):
        import teardown as standalone
        state = self.prepare()
        with mock.patch.object(azure, 'cleanup_azure', return_value=True) as execute, mock.patch.object(standalone, 'cleanup_ssh_keys') as keys, mock.patch.object(standalone, 'archive_logs') as archive, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(standalone.teardown_deployment(state['deployment_id'], force=True))
            self.assertEqual(execute.call_args.args[0]['provider'], 'azure')
            keys.assert_not_called()
            archive.assert_not_called()

    def test_standalone_teardown_invalid_state_does_not_fall_back_to_logs(self):
        import teardown as standalone
        with mock.patch.object(registry, 'load_infrastructure_state', side_effect=ValueError('invalid')), mock.patch.object(standalone.glob, 'glob') as logs, contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(standalone.teardown_deployment('test-azure', force=True))
            logs.assert_not_called()

    def test_standalone_teardown_confirmation_and_failure_exit_status(self):
        import teardown as standalone
        state = self.prepare()
        with mock.patch('builtins.input', return_value='no'), mock.patch.object(azure, 'cleanup_azure') as execute, contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(standalone.teardown_deployment(state['deployment_id']))
            execute.assert_not_called()
        with mock.patch.object(sys, 'argv', ['teardown.py', '--deployment-id', 'test-azure', '--force']), mock.patch.object(standalone, 'teardown_deployment', return_value=False), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(standalone.main(), 1)

    def test_standalone_teardown_missing_adapter_state_keeps_legacy_lookup(self):
        import teardown as standalone
        with mock.patch.object(registry, 'load_infrastructure_state', return_value=None), mock.patch.object(standalone.glob, 'glob', return_value=[]) as logs, mock.patch.object(standalone, 'list_deployments'), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(standalone.teardown_deployment('Old_ID', force=True))
            logs.assert_called_once_with('logs/deployment_info_Old_ID*.txt')

    def test_standalone_cleanup_uses_registered_route_before_legacy(self):
        import teardown as standalone

        config = {'provider': 'aws', 'provider_workload': 'c2',
                  'deployment_id': 'legacy-1'}
        with mock.patch.object(
                standalone, 'execute_legacy_teardown', return_value=False) as legacy:
            self.assertFalse(standalone.execute_teardown(config))
        legacy.assert_called_once_with(config)

        native = mock.Mock()
        spec = registry.PROVIDER_SPECS['aws']._replace(
            routes={'c2': 'synthetic:Adapter'})
        with mock.patch.dict(registry.PROVIDER_SPECS, {'aws': spec}), \
                mock.patch.object(registry, '_load', return_value=lambda: native), \
                mock.patch.object(standalone, 'execute_legacy_teardown') as legacy:
            native.cleanup.return_value = False
            self.assertFalse(standalone.execute_teardown(config))
            legacy.assert_not_called()
            native.cleanup.side_effect = RuntimeError('new cleanup failed')
            with self.assertRaisesRegex(RuntimeError, 'new cleanup failed'):
                standalone.execute_teardown(config)
            legacy.assert_not_called()

        missing = {**config, 'provider_workload': 'unmigrated'}
        with mock.patch.object(
                standalone, 'execute_legacy_teardown', return_value=True) as legacy:
            self.assertTrue(standalone.execute_teardown(missing))
        legacy.assert_called_once_with(missing)

    def test_standalone_discovery_merges_state_and_logs_with_adapter_priority(self):
        import teardown as standalone
        state = self.prepare()
        legacy = {'provider': 'aws', 'deployment_id': 'legacy-1'}
        with mock.patch.object(standalone.glob, 'glob', return_value=['azure.txt', 'legacy.txt']), mock.patch.object(standalone, 'parse_deployment_info', side_effect=[{'provider': 'azure', 'deployment_id': state['deployment_id']}, legacy]):
            deployments, adapter_ids = standalone.discover_deployments()
            self.assertEqual(deployments, [state, legacy])
            self.assertEqual(adapter_ids, {state['deployment_id']})
        output = io.StringIO()
        with mock.patch.object(standalone.glob, 'glob', return_value=[]), contextlib.redirect_stdout(output):
            self.assertTrue(standalone.list_deployments())
        self.assertIn(state['deployment_id'], output.getvalue())
        self.assertIn('azure', output.getvalue())

    def test_standalone_discovery_refuses_ambiguous_and_unreadable_records(self):
        import teardown as standalone
        state = self.prepare()
        cases = [None, {}, {'provider': 'aws', 'deployment_id': state['deployment_id']}]
        for record in cases:
            with self.subTest(record=record), mock.patch.object(standalone.glob, 'glob', return_value=['bad.txt']), mock.patch.object(standalone, 'parse_deployment_info', return_value=record), mock.patch.object(azure, 'cleanup_azure') as adapter, mock.patch.object(standalone, 'execute_teardown') as legacy, contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(standalone.teardown_all_deployments(force=True))
                adapter.assert_not_called()
                legacy.assert_not_called()
        with mock.patch.object(registry, 'list_infrastructure_states', return_value=[state, state]), contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(standalone.discover_deployments())
        with mock.patch.object(registry, 'list_infrastructure_states', side_effect=ValueError('bad state')), mock.patch.object(standalone.glob, 'glob') as logs, contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(standalone.teardown_all_deployments(force=True))
            logs.assert_not_called()

    def test_standalone_batch_preserves_legacy_cleanup_and_never_retries_failed_adapter(self):
        import teardown as standalone
        state = self.prepare()
        legacy = {'provider': 'aws', 'deployment_id': 'legacy-1'}
        for adapter_ok in (True, False):
            with self.subTest(adapter_ok=adapter_ok), mock.patch.object(standalone.glob, 'glob', return_value=['legacy.txt']), mock.patch.object(standalone, 'parse_deployment_info', return_value=legacy), mock.patch.object(azure, 'cleanup_azure', return_value=adapter_ok) as adapter, mock.patch.object(standalone, 'execute_teardown', return_value=True) as execute, mock.patch.object(standalone, 'cleanup_ssh_keys') as keys, mock.patch.object(standalone, 'archive_logs') as archive, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(standalone.teardown_all_deployments(force=True), adapter_ok)
                adapter.assert_called_once_with(state)
                execute.assert_called_once_with(legacy)
                keys.assert_called_once_with('legacy-1')
                archive.assert_called_once_with('legacy-1')

    def test_standalone_batch_cancellation_and_missing_adapter_prevent_legacy_cleanup(self):
        import teardown as standalone
        state = self.prepare()
        with mock.patch.object(standalone.glob, 'glob', return_value=[]), mock.patch('builtins.input', return_value='no'), mock.patch.object(azure, 'cleanup_azure') as adapter, contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(standalone.teardown_all_deployments())
            adapter.assert_not_called()
        with mock.patch.object(registry, 'infrastructure_adapter', return_value=None), mock.patch.object(standalone, 'execute_teardown') as legacy, contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(standalone.teardown_adapter_state(state, force=True))
            legacy.assert_not_called()

    def test_standalone_selection_uses_discovered_adapter_state(self):
        import teardown as standalone
        state = self.prepare()
        with mock.patch.object(standalone.glob, 'glob', return_value=[]), mock.patch('builtins.input', side_effect=['1', 'yes']), mock.patch.object(azure, 'cleanup_azure', return_value=True) as adapter, mock.patch.object(standalone, 'teardown_deployment') as by_id, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(standalone.select_and_teardown_deployment())
            adapter.assert_called_once_with(state)
            by_id.assert_not_called()

    def test_standalone_discovery_refuses_azure_logs_without_recovery_state(self):
        import teardown as standalone
        log = {'provider': 'azure', 'deployment_id': 'missing-state'}
        with mock.patch.object(standalone.glob, 'glob', return_value=['stale.txt']), mock.patch.object(standalone, 'parse_deployment_info', return_value=log), mock.patch.object(standalone, 'execute_teardown') as legacy, contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(standalone.teardown_all_deployments(force=True))
            legacy.assert_not_called()

    def test_standalone_batch_records_adapter_exception_and_continues_other_cleanup(self):
        import teardown as standalone
        self.prepare()
        legacy = {'provider': 'aws', 'deployment_id': 'legacy-1'}
        with mock.patch.object(standalone.glob, 'glob', return_value=['legacy.txt']), mock.patch.object(standalone, 'parse_deployment_info', return_value=legacy), mock.patch.object(azure, 'cleanup_azure', side_effect=RuntimeError('unavailable')), mock.patch.object(standalone, 'execute_teardown', return_value=True) as execute, mock.patch.object(standalone, 'cleanup_ssh_keys'), mock.patch.object(standalone, 'archive_logs'), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(standalone.teardown_all_deployments(force=True))
            execute.assert_called_once_with(legacy)

    def test_standalone_cli_propagates_discovery_and_cleanup_failures(self):
        import teardown as standalone
        for flag, function in [('--list', 'list_deployments'), ('--all', 'teardown_all_deployments'), ('--select', 'select_and_teardown_deployment')]:
            for success in (True, False):
                with self.subTest(flag=flag, success=success), mock.patch.object(sys, 'argv', ['teardown.py', flag]), mock.patch.object(standalone, function, return_value=success), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(standalone.main(), 0 if success else 1)

    def test_legacy_imports_do_not_load_azure_adapter_or_runtime(self):
        result = subprocess.run([sys.executable, '-B', '-c',
            "import sys; from utils import provider_utils, deployment_engine, cleanup_engine; "
            "assert 'utils.azure_adapter' not in sys.modules; "
            "assert 'utils.azure_utils' not in sys.modules; "
            "assert provider_utils.available_providers() == ['aws', 'linode', 'flokinet']"],
            cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_provider_uses_dispatcher_and_original_configuration_loader(self):
        from utils import aws_utils, linode_utils, flokinet_utils
        for name, module, function in (
            ('aws', aws_utils, 'gather_aws_config'),
            ('linode', linode_utils, 'gather_linode_config'),
            ('flokinet', flokinet_utils, 'gather_flokinet_config'),
            ('azure', azure, 'gather_azure_config'),
        ):
            with self.subTest(provider=name), mock.patch.object(module, function, return_value={'provider': name}) as gather:
                self.assertEqual(registry.provider_dispatcher(name).provider, name)
                self.assertEqual(provider_utils.gather_provider_config(name), {'provider': name})
                gather.assert_called_once_with()

    def test_main_menu_lists_generic_adapter_state_without_azure_import(self):
        import deploy

        state = {'provider': 'example', 'deployment_id': 'generic-1',
                 'status': 'ready'}
        output = io.StringIO()
        previous = Path.cwd()
        try:
            os.chdir(self.home)
            with mock.patch.object(
                    registry, 'list_infrastructure_states', return_value=[state]) as states, \
                    mock.patch.object(deploy, 'wait_for_input'), \
                    contextlib.redirect_stdout(output):
                deploy.list_deployments()
        finally:
            os.chdir(previous)

        states.assert_called_once_with()
        self.assertIn('Example generic-1: ready', output.getvalue())
        self.assertIn('Found 1 deployment records', output.getvalue())

    def test_registered_workload_precedes_legacy_and_failure_never_falls_back(self):
        spec = registry.PROVIDER_SPECS['aws']._replace(routes={'infrastructure': 'synthetic:Adapter'})
        adapter = mock.Mock()
        config = {**self.config, 'provider': 'aws'}
        with mock.patch.dict(registry.PROVIDER_SPECS, {'aws': spec}), mock.patch.object(registry, '_load', return_value=lambda: adapter), mock.patch.object(deployment_engine, 'execute_playbook') as legacy:
            adapter.deploy.return_value = False
            self.assertFalse(deployment_engine.deploy_infrastructure(config))
            legacy.assert_not_called()
            adapter.deploy.side_effect = RuntimeError('new route failed')
            with self.assertRaisesRegex(RuntimeError, 'new route failed'):
                deployment_engine.deploy_infrastructure(config)
            legacy.assert_not_called()
            adapter.cleanup.return_value = False
            with mock.patch.object(cleanup_engine, 'run_teardown_playbook') as old_cleanup:
                self.assertFalse(cleanup_engine.execute_teardown(config))
                old_cleanup.assert_not_called()

    def test_legacy_routes_do_not_import_unrelated_new_adapter(self):
        spec = registry.PROVIDER_SPECS['aws']._replace(routes={'infrastructure': 'unavailable:Adapter'})
        with mock.patch.dict(registry.PROVIDER_SPECS, {'aws': spec}), mock.patch.object(registry, '_load', side_effect=AssertionError('unexpected adapter import')):
            cases = [({}, 'c2'), ({'attack_box_deployment': True}, 'attack_box'),
                     ({'redirector_only': True}, 'redirector'), ({'tracker_deployment': True}, 'tracker'),
                     ({'chat_deployment': True}, 'chat_server'), ({'c2_only': True}, 'c2')]
            for flags, playbook in cases:
                self.assertEqual(deployment_engine.determine_playbook({'provider': 'aws', **flags}),
                                 f'providers/AWS/{playbook}.yml')
            config = {'provider': 'aws', 'deployment_id': 'legacy', 'chat_deployment': True}
            with mock.patch('utils.common.setup_logging'), mock.patch.object(cleanup_engine, 'set_provider_environment_for_teardown'), mock.patch.object(cleanup_engine, 'run_teardown_playbook', return_value=False) as legacy:
                self.assertFalse(cleanup_engine.execute_teardown(config))
                legacy.assert_called_once_with('providers/AWS/cleanup.yml', config)

    def test_missing_new_route_preserves_existing_deployment_path_for_each_provider(self):
        for provider, directory in (('aws', 'AWS'), ('linode', 'Linode'), ('flokinet', 'FlokiNET')):
            config = {'provider': provider, 'deployment_id': 'legacy', 'deployment_type': 'unmigrated'}
            with self.subTest(provider=provider), mock.patch.object(deployment_engine, 'set_provider_environment') as env, mock.patch.object(deployment_engine, 'execute_playbook', return_value=True) as legacy:
                self.assertTrue(deployment_engine.deploy_infrastructure(config))
                env.assert_called_once_with(config)
                legacy.assert_called_once_with(f'providers/{directory}/c2.yml', config)

    def test_generic_module_runs_a_registered_adapter_without_azure_imports(self):
        spec = importlib.util.spec_from_file_location('generic_infrastructure', ROOT / 'modules/infrastructure/deploy_infrastructure.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        adapter = mock.Mock()
        adapter.validate_config.side_effect = lambda config, **kwargs: dict(config)
        adapter.prepare_key.return_value = True
        with mock.patch.object(module, 'select_provider', return_value='example'), mock.patch.object(module, 'infrastructure_adapter', return_value=adapter), mock.patch.object(module, 'gather_provider_config', return_value={}), mock.patch.object(module, 'generate_deployment_id', return_value='generic-test'), mock.patch.object(module, 'setup_logging'), mock.patch('builtins.input', return_value=str(self.key) + '.pub'), mock.patch.object(module, 'deploy_infrastructure', return_value=True) as deploy, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(module.main([]))
            config = deploy.call_args.args[0]
            self.assertEqual(config['provider'], 'example')
            self.assertFalse(any(key.startswith('azure_') for key in config))
            adapter.prepare_key.assert_called_once()

    def test_missing_capability_menu_exits_without_prompting(self):
        with mock.patch('builtins.input') as prompt, contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(provider_utils.select_provider('missing-workload'))
            prompt.assert_not_called()

    def test_recovery_refuses_ambiguous_cross_provider_id(self):
        adapter_a = mock.Mock()
        adapter_b = mock.Mock()
        adapter_a.load_state.return_value = {'provider': 'azure'}
        adapter_b.load_state.return_value = {'provider': 'second'}
        with mock.patch.object(registry, 'providers_for', return_value=['azure', 'second']), mock.patch.object(registry, 'infrastructure_adapter', side_effect=[adapter_a, adapter_b]):
            with self.assertRaisesRegex(ValueError, 'multiple providers'):
                registry.load_infrastructure_state('same-id')

    def test_connectivity_requires_real_arm_response_and_matching_subscription(self):
        account = subprocess.CompletedProcess([], 0, json.dumps({'id': smoke.SUBSCRIPTION, 'state': 'Enabled'}), '')
        with mock.patch.object(azure, 'run_command', return_value=account), mock.patch.object(azure, 'run_az', return_value=0) as arm:
            result = azure.check_connection(smoke.SUBSCRIPTION)
            self.assertEqual(result['resource_group_count'], 0)
            arm.assert_called_once_with(['group', 'list', '--query', 'length(@)'], smoke.SUBSCRIPTION)
        with mock.patch.object(azure, 'run_command', return_value=account), mock.patch.object(azure, 'run_az') as arm:
            with self.assertRaisesRegex(ValueError, 'different subscription'):
                azure.check_connection('00000000-0000-0000-0000-000000000000')
            arm.assert_not_called()

    def test_key_cleanup_preserves_active_keys_and_removes_only_unused_candidates(self):
        import deploy as app
        self.prepare()
        unused = self.key.parent / 'c2deploy_unused'
        unused.write_text('unused')
        with mock.patch('builtins.input', return_value='y'), mock.patch.object(app, 'wait_for_input'), contextlib.redirect_stdout(io.StringIO()):
            app.clean_ssh_keys()
        self.assertTrue(self.key.exists())
        self.assertTrue(Path(str(self.key) + '.pub').exists())
        self.assertFalse(unused.exists())

    def test_key_cleanup_fails_closed_on_invalid_state_or_state_change_during_prompt(self):
        import deploy as app
        with mock.patch.object(registry, 'list_infrastructure_states', side_effect=ValueError('corrupt')), mock.patch('builtins.input') as prompt, mock.patch.object(app, 'wait_for_input'), contextlib.redirect_stdout(io.StringIO()):
            app.clean_ssh_keys()
            prompt.assert_not_called()
        self.assertTrue(self.key.exists())
        state = {'ssh_key_path': str(self.key) + '.pub', 'ssh_private_key_path': str(self.key)}
        with mock.patch.object(registry, 'list_infrastructure_states', side_effect=[[], [state]]), mock.patch('builtins.input', return_value='y'), mock.patch.object(app, 'wait_for_input'), contextlib.redirect_stdout(io.StringIO()):
            app.clean_ssh_keys()
        self.assertTrue(self.key.exists())


class ProcessTests(unittest.TestCase):
    def test_hung_command_is_bounded(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            azure.run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.1)
        self.assertLess(time.monotonic() - started, 5)

    def test_command_error_propagates(self):
        with self.assertRaises(RuntimeError):
            azure.run_command([sys.executable, "-c", "import sys;sys.exit(7)"])

    def test_deadline_prevents_child_start(self):
        with mock.patch.object(azure.subprocess, "Popen") as start, self.assertRaises(TimeoutError):
            azure.run_command(["unused"], deadline=time.monotonic() - 1)
        start.assert_not_called()

    def test_sigint_and_sigterm_stop_child_process_group(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig):
                code = f'''import os,sys,threading,time,signal
sys.path.insert(0,{str(ROOT)!r})
from utils import azure_utils as a
threading.Timer(0.3, lambda: os.kill(os.getpid(), {int(sig)})).start()
try:
    a.run_command([sys.executable, '-c', 'import time;time.sleep(30)'], timeout=15)
except KeyboardInterrupt:
    print('interrupted')
else:
    raise AssertionError('signal was not propagated')
'''
                result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("interrupted", result.stdout)


class SmokeTests(unittest.TestCase):
    def test_infrastructure_live_harness_dry_run_has_no_cloud_calls(self):
        harness_spec = importlib.util.spec_from_file_location(
            'azure_infrastructure_live',
            ROOT / 'scripts/test_azure_infrastructure_live.py')
        harness = importlib.util.module_from_spec(harness_spec)
        harness_spec.loader.exec_module(harness)
        with mock.patch.object(harness, 'activate') as activate, contextlib.redirect_stdout(
                io.StringIO()):
            self.assertEqual(harness.main([]), 0)
        activate.assert_not_called()

    def monitoring_fixture(self):
        runner = smoke.Runner()
        runner.deadline = time.monotonic() + 60
        runner.subscription_baseline = {'resource': [], 'group': []}
        group = f'/subscriptions/{smoke.SUBSCRIPTION}/resourceGroups/NetworkWatcherRG'
        watcher = group + '/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus'
        inventory = {'resource': [watcher.lower()], 'group': [group.lower()]}
        details = {'id': watcher, 'location': 'eastus', 'properties': {'runningOperationIds': []}}
        children = {'value': []}
        calls = []
        def cloud(*args):
            calls.append(args)
            if args[:2] == ('resource', 'show'):
                return details
            if args[:1] == ('rest',):
                return children
            if args[:2] == ('resource', 'delete'):
                inventory['resource'] = []
                return None
            if args[:2] == ('group', 'delete'):
                inventory['group'] = []
                return None
            if args[:2] == ('group', 'exists'):
                return bool(inventory['group'])
            raise AssertionError(f'Unexpected cleanup command {args}')
        return runner, inventory, details, children, calls, cloud

    def test_subscription_cleanup_removes_only_idle_monitoring_from_empty_lab(self):
        runner, inventory, details, children, calls, cloud = self.monitoring_fixture()
        with mock.patch.object(runner, 'inventory', side_effect=lambda: copy.deepcopy(inventory)), mock.patch.object(runner, 'az', side_effect=cloud), mock.patch.object(runner, 'record') as record:
            runner.cleanup_subscription()
        self.assertEqual(inventory, runner.subscription_baseline)
        self.assertEqual(sum(call[:2] == ('resource', 'delete') for call in calls), 1)
        self.assertEqual(sum(call[:2] == ('group', 'delete') for call in calls), 1)
        self.assertTrue(record.call_args.args[1]['restored'])

    def test_subscription_cleanup_preserves_preexisting_resources_and_monitoring(self):
        runner, inventory, details, children, calls, cloud = self.monitoring_fixture()
        runner.subscription_baseline = copy.deepcopy(inventory)
        with mock.patch.object(runner, 'inventory', return_value=inventory), mock.patch.object(runner, 'az') as az, mock.patch.object(runner, 'record'):
            runner.cleanup_subscription()
            az.assert_not_called()

    def test_subscription_cleanup_refuses_foreign_resources_and_missing_baseline(self):
        for baseline in (None, {'resource': ['/existing'], 'group': ['/existing-group']}):
            runner, inventory, details, children, calls, cloud = self.monitoring_fixture()
            runner.subscription_baseline = baseline
            with mock.patch.object(runner, 'inventory', return_value=inventory), mock.patch.object(runner, 'az') as az, mock.patch.object(runner, 'record'), self.assertRaises(smoke.SmokeError):
                runner.cleanup_subscription()
            az.assert_not_called()
        runner, inventory, details, children, calls, cloud = self.monitoring_fixture()
        inventory['resource'].append('/unexpected-vm')
        with mock.patch.object(runner, 'inventory', return_value=inventory), mock.patch.object(runner, 'az') as az, mock.patch.object(runner, 'record'), self.assertRaises(smoke.SmokeError):
            runner.cleanup_subscription()
        az.assert_not_called()

    def test_subscription_cleanup_preserves_monitoring_with_data_or_uncertain_response(self):
        for page in ({'value': [{'id': 'existing-monitor'}]}, {}, {'value': [], 'nextLink': 'next'}):
            runner, inventory, details, children, calls, cloud = self.monitoring_fixture()
            children.clear()
            children.update(page)
            with mock.patch.object(runner, 'inventory', return_value=inventory), mock.patch.object(runner, 'az', side_effect=cloud), mock.patch.object(runner, 'record'), self.assertRaises(smoke.SmokeError):
                runner.cleanup_subscription()
            self.assertFalse(any(call[1:2] == ('delete',) for call in calls))

    def test_subscription_cleanup_preserves_busy_or_wrong_identity_watcher(self):
        for field, value in (('id', '/foreign'), ('location', 'westus'), ('properties', {'runningOperationIds': ['busy']})):
            runner, inventory, details, children, calls, cloud = self.monitoring_fixture()
            details[field] = value
            with mock.patch.object(runner, 'inventory', return_value=inventory), mock.patch.object(runner, 'az', side_effect=cloud), mock.patch.object(runner, 'record'), self.assertRaises(smoke.SmokeError):
                runner.cleanup_subscription()
            self.assertFalse(any(call[1:2] == ('delete',) for call in calls))

    def test_subscription_cleanup_rechecks_before_deleting_monitoring(self):
        runner, inventory, details, children, calls, cloud = self.monitoring_fixture()
        changed = copy.deepcopy(inventory)
        changed['resource'].append('/concurrent-vm')
        with mock.patch.object(runner, 'inventory', side_effect=[inventory, changed]), mock.patch.object(runner, 'az', side_effect=cloud), mock.patch.object(runner, 'record'), self.assertRaises(smoke.SmokeError):
            runner.cleanup_subscription()
        self.assertFalse(any(call[1:2] == ('delete',) for call in calls))

    def test_cleanup_cannot_report_success_when_subscription_cleanup_fails(self):
        runner = smoke.Runner()
        config = {'azure_resource_group': 'test', 'deployment_id': 'test'}
        with mock.patch.object(runner, 'worker'), mock.patch.object(runner, 'az', return_value=False), mock.patch.object(runner, 'cleanup_subscription', side_effect=smoke.SmokeError('residual')), mock.patch.object(runner, 'record'), contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(runner.cleanup(ROOT, config))

    def verification_fixture(self, disk_field="diskSizeGB", disk_size=32):
        """CLI response structure with synthetic identifiers, never live evidence."""
        base = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-smoke/providers/"
        vm_id = base + "Microsoft.Compute/virtualMachines/test-vm"
        disk_id = base + "Microsoft.Compute/disks/test-osdisk"
        vm = {
            "id": vm_id, "name": "test-vm", "location": "eastus",
            "hardwareProfile": {"vmSize": smoke.SIZE},
            "storageProfile": {
                "imageReference": {"publisher": "Canonical", "offer": "ubuntu-24_04-lts",
                                   "sku": "server", "version": "latest", "exactVersion": "24.04.202601010"},
                "osDisk": {disk_field: disk_size, "caching": "ReadWrite", "createOption": "FromImage",
                           "deleteOption": "Delete", "name": "test-osdisk", "osType": "Linux",
                           "managedDisk": {"id": disk_id, "resourceGroup": "test-smoke", "storageAccountType": "StandardSSD_LRS"}},
            },
            "osProfile": {"adminUsername": "azureuser", "linuxConfiguration": {
                "disablePasswordAuthentication": True, "provisionVMAgent": True,
                "ssh": {"publicKeys": [{"path": "/home/azureuser/.ssh/authorized_keys", "keyData": "synthetic-public-key"}]}}},
            "diagnosticsProfile": {"bootDiagnostics": {"enabled": True}},
            "provisioningState": "Succeeded",
        }
        ips = [{"id": base + "Microsoft.Network/publicIPAddresses/test-ip", "sku": {"name": "Standard"},
                "publicIPAllocationMethod": "Static", "publicIPAddressVersion": "IPv4", "ipAddress": "8.8.4.4"}]
        nsgs = [{"id": base + "Microsoft.Network/networkSecurityGroups/test-nsg", "securityRules": [
            {"name": "ssh", "direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "8.8.8.8/32",
             "destinationPortRange": "22", "protocol": "Tcp", "priority": 100},
            {"name": "deny-other", "direction": "Inbound", "access": "Deny", "sourceAddressPrefix": "*",
             "destinationPortRange": "*", "protocol": "*", "priority": 200},
        ]}]
        resources = [{"id": vm_id}, {"id": disk_id}, {"id": ips[0]["id"]}, {"id": nsgs[0]["id"]}]
        config = {"azure_resource_group": "test-smoke", "operator_ip": "8.8.8.8/32",
                  "ssh_private_key_path": "/synthetic/c2deploy_test-smoke"}
        runner = smoke.Runner()
        runner.evidence = Path("/synthetic/evidence")
        runner.deadline = time.monotonic() + 60
        def cloud(*args):
            if args[:2] == ("vm", "list"):
                return [copy.deepcopy(vm)]
            if args[:3] == ("network", "public-ip", "list"):
                return copy.deepcopy(ips)
            if args[:3] == ("network", "nsg", "list"):
                return copy.deepcopy(nsgs)
            if args[:2] == ("resource", "list"):
                return copy.deepcopy(resources)
            raise AssertionError(f"Unexpected verification call: {args}")
        return runner, config, vm, cloud

    def test_full_verifier_accepts_current_and_legacy_disk_size_fields(self):
        for spelling in ("diskSizeGB", "diskSizeGb"):
            with self.subTest(spelling=spelling):
                runner, config, vm, cloud = self.verification_fixture(spelling)
                with mock.patch.object(runner, "az", side_effect=cloud) as az, mock.patch.object(runner, "run", return_value="active") as ssh, mock.patch.object(runner, "worker") as repeat, mock.patch.object(runner, "record") as record:
                    runner.verify(config, ROOT)
                    ssh.assert_called_once()
                    argv = ssh.call_args.args[0]
                    self.assertEqual(argv[:3], ["ssh", "-F", "/dev/null"])
                    self.assertIn("StrictHostKeyChecking=accept-new", argv)
                    self.assertIn("UserKnownHostsFile=/synthetic/evidence/known_hosts", argv)
                    self.assertEqual(ssh.call_args.kwargs["timeout"], 30)
                    self.assertEqual(repeat.call_args_list[0].args, (ROOT, "deploy", config))
                    self.assertLessEqual(repeat.call_args_list[0].kwargs["timeout"], 60)
                    self.assertEqual(repeat.call_args_list[1].args, (ROOT, "health", config))
                    self.assertEqual(sum(call.args[:2] == ("vm", "list") for call in az.call_args_list), 2)
                    self.assertEqual(sum(call.args[:2] == ("resource", "list") for call in az.call_args_list), 2)
                    result = record.call_args.args[1]
                    self.assertEqual(record.call_args.args[0], "validation.json")
                    self.assertEqual(result["vm_id"], vm["id"])
                    self.assertEqual(result["ssh"], "passed")
                    self.assertEqual(result["repeat"], "passed")

    def test_full_verifier_rejects_wrong_or_ambiguous_disk_sizes_before_ssh(self):
        for spelling in ("diskSizeGB", "diskSizeGb"):
            for value in (31, 64, "32", 32.0, True, None):
                with self.subTest(spelling=spelling, value=value):
                    runner, config, vm, cloud = self.verification_fixture(spelling, value)
                    with mock.patch.object(runner, "az", side_effect=cloud), mock.patch.object(runner, "run") as ssh, mock.patch.object(runner, "worker") as repeat:
                        with self.assertRaisesRegex(smoke.SmokeError, "OS disk"):
                            runner.verify(config, ROOT)
                        ssh.assert_not_called()
                        repeat.assert_not_called()
        for sizes in ({}, {"diskSizeGB": 32, "diskSizeGb": 64}):
            with self.subTest(sizes=sizes):
                runner, config, vm, cloud = self.verification_fixture()
                disk = vm["storageProfile"]["osDisk"]
                disk.pop("diskSizeGB")
                disk.update(sizes)
                with mock.patch.object(runner, "az", side_effect=cloud), self.assertRaisesRegex(smoke.SmokeError, "OS disk"):
                    runner.verify(config, ROOT)

    def quota_preflight(self, usage):
        """Exercise the real preflight through quota checks, stopping before image I/O."""
        runner = smoke.Runner()
        sku = {"family": "standardDASv4Family", "capabilities": [{"name": "vCPUs", "value": "2"}]}
        def cloud(*args):
            if args[:2] == ("provider", "show"):
                return {"registrationState": "Registered"}
            if args[:2] == ("vm", "list-usage"):
                return usage
            if args[:3] == ("vm", "image", "show"):
                raise LookupError("quota checks passed")
            raise AssertionError(f"Unexpected cloud call: {args}")
        with mock.patch.object(runner, "az", side_effect=cloud), mock.patch.object(runner, "find_sku", return_value=sku):
            runner.register_and_preflight(ROOT, {})

    def test_quota_normalizes_decimal_strings_and_integers(self):
        for value, expected in ((0, 0), (4, 4), ("0", 0), ("004", 4)):
            with self.subTest(value=value):
                self.assertEqual(smoke.nonnegative_count(value, "test"), expected)
        for current, limit in (("0", "4"), (0, 4), ("2", 4), (2, "4")):
            usage = [{"name": {"value": name}, "currentValue": current, "limit": limit}
                     for name in ("cores", "standardDASv4Family")]
            with self.subTest(current=current, limit=limit), self.assertRaisesRegex(LookupError, "quota checks passed"):
                self.quota_preflight(usage)

    def test_insufficient_regional_or_family_quota_is_refused(self):
        for insufficient_name in ("cores", "standardDASv4Family"):
            usage = [{"name": {"value": name}, "currentValue": "3" if name == insufficient_name else "0", "limit": "4"}
                     for name in ("cores", "standardDASv4Family")]
            with self.subTest(quota=insufficient_name), self.assertRaisesRegex(smoke.SmokeError, "Insufficient quota"):
                self.quota_preflight(usage)

    def test_malformed_quota_counts_are_refused(self):
        invalid = (True, False, -1, "-1", "+1", " 1", "1 ", "1.0", 1.0, "", None, "abc", "١", "1e3")
        for field in ("currentValue", "limit"):
            for value in invalid:
                usage = [{"name": {"value": "cores"}, "currentValue": "0", "limit": "4", field: value}]
                with self.subTest(field=field, value=value), self.assertRaisesRegex(smoke.SmokeError, "nonnegative decimal count"):
                    self.quota_preflight(usage)

    def test_dry_run_performs_no_commands_or_writes(self):
        with mock.patch.object(smoke.subprocess, "Popen") as process, mock.patch.object(smoke.Path, "open") as write, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(smoke.main(["--dry-run"]), 0)
            self.assertEqual(smoke.main([]), 0)
        process.assert_not_called()
        write.assert_not_called()

    def test_unexpected_staged_paths_stop_before_checks_or_push(self):
        runner = smoke.Runner()
        with mock.patch.object(runner, "git", return_value="foreign.txt\0") as git, mock.patch.object(runner, "run") as run:
            with self.assertRaises(smoke.SmokeError):
                runner.commit_and_push()
            self.assertEqual(git.call_count, 1)
            run.assert_not_called()

    def test_sku_lookup_pages_and_stops_at_approved_size(self):
        runner = smoke.Runner()
        next_link = f"https://management.azure.com/subscriptions/{smoke.SUBSCRIPTION}/next"
        target = {"name": smoke.SIZE, "resourceType": "virtualMachines"}
        with mock.patch.object(runner, "az", side_effect=[{"value": [], "nextLink": next_link}, {"value": [target], "nextLink": next_link + "unused"}]) as cloud:
            self.assertEqual(runner.find_sku(), target)
            self.assertEqual(cloud.call_count, 2)
            self.assertIn("location%20eq%20%27eastus%27", cloud.call_args_list[0].args[-1])

    def test_wrong_subscription_is_refused(self):
        runner = smoke.Runner()
        with mock.patch.object(runner, "git", side_effect=[str(ROOT), "public", "forgejo-url"]), mock.patch.object(smoke.shutil, "which", return_value="tool"), mock.patch.object(runner, "az", return_value={"id": "wrong", "state": "Enabled"}):
            with self.assertRaisesRegex(smoke.SmokeError, "subscription"):
                runner.validate()

    def test_existing_group_stops_before_baseline_acceptance(self):
        runner = smoke.Runner()
        with mock.patch.object(runner, "az", return_value=True), mock.patch.object(runner, "record") as record:
            with self.assertRaises(smoke.SmokeError):
                runner.baseline("existing-group")
            record.assert_not_called()

    def test_wrong_branch_stops_before_cloud_calls(self):
        runner = smoke.Runner()
        with mock.patch.object(runner, "git", side_effect=[str(ROOT), "other"]), mock.patch.object(runner, "az") as cloud:
            with self.assertRaises(smoke.SmokeError):
                runner.validate()
            cloud.assert_not_called()

    def test_push_failure_prevents_artifact_and_cloud_mutations(self):
        runner = smoke.Runner()
        def git(*args, **kwargs):
            if args[0] == "push":
                raise smoke.SmokeError("push failed")
            return "sha" if args == ("rev-parse", "HEAD") else ""
        with mock.patch.object(runner, "git", side_effect=git), mock.patch.object(runner, "run"), mock.patch.object(runner, "archive") as archive:
            with self.assertRaisesRegex(smoke.SmokeError, "push failed"):
                runner.commit_and_push()
            archive.assert_not_called()

    def test_remote_sha_mismatch_is_refused(self):
        runner = smoke.Runner()
        def git(*args, **kwargs):
            if args == ("rev-parse", "HEAD"):
                return "expected"
            if args[0] == "ls-remote":
                return "different refs/heads/public"
            return ""
        with mock.patch.object(runner, "git", side_effect=git), mock.patch.object(runner, "run"):
            with self.assertRaisesRegex(smoke.SmokeError, "exact deployment commit"):
                runner.commit_and_push()

    def test_signal_handler_preserves_cleanup_window(self):
        runner = smoke.Runner()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.assertRaises(smoke.SmokeInterrupted):
                runner.handle_signal(sig, None)
        runner.cleaning = True
        runner.handle_signal(signal.SIGTERM, None)
        self.assertTrue(runner.interrupted)

    def test_failed_cleanup_cannot_produce_success(self):
        runner = mock.Mock()
        runner.root = ROOT
        runner.evidence = None
        runner.interrupted = False
        runner.archive.return_value = ROOT
        runner.cleanup.return_value = False
        with mock.patch.object(smoke, "Runner", return_value=runner), mock.patch.object(smoke.Path, "exists", return_value=False), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(smoke.activate("8.8.8.8"), 1)
        runner.cleanup.assert_called_once()
        runner.verify.assert_called_once()

    def test_preflight_failure_still_cleans_up_without_deploying(self):
        runner = mock.Mock()
        runner.root = ROOT
        runner.evidence = None
        runner.interrupted = False
        runner.archive.return_value = ROOT
        runner.register_and_preflight.side_effect = smoke.SmokeError("quota")
        runner.cleanup.return_value = True
        with mock.patch.object(smoke, "Runner", return_value=runner), mock.patch.object(smoke.Path, "exists", return_value=False), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(smoke.activate("8.8.8.8"), 1)
        runner.cleanup.assert_called_once()
        runner.verify.assert_not_called()
        self.assertEqual([call.args[1] for call in runner.worker.call_args_list], ["key"])

    def test_prepare_never_deploys_or_verifies_and_records_separate_result(self):
        runner = mock.Mock()
        runner.root = ROOT
        runner.evidence = ROOT / "logs" / "test-evidence"
        runner.interrupted = False
        runner.archive.return_value = ROOT
        runner.cleanup.return_value = True
        with mock.patch.object(smoke, "Runner", return_value=runner), mock.patch.object(smoke.Path, "exists", return_value=False), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(smoke.activate("8.8.8.8", prepare_only=True), 0)
        runner.register_and_preflight.assert_called_once()
        runner.cleanup.assert_called_once()
        runner.verify.assert_not_called()
        self.assertEqual([call.args[1] for call in runner.worker.call_args_list], ["key"])
        result = next(call.args[1] for call in runner.record.call_args_list if call.args[0] == "result.json")
        self.assertTrue(result["prepared"])
        self.assertFalse(result["passed"])
        self.assertFalse(result["validation_passed"])
        self.assertIn("prepared=true", output.getvalue())
        self.assertNotIn("smoke passed", output.getvalue())


if __name__ == "__main__":
    unittest.main()
