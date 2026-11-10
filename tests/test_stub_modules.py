"""The completed stubs and the edge (CDN fronting) contract."""

import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests import fake_cloud
from utils import azure_cloud, azure_utils, deployment_engine
from utils import provider_registry as registry
from utils.vm_workloads import SingleVmAdapter
from utils.workloads import host_source, load_profile

PUBLIC_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderKeyMaterial0000000000000000000 test\n'


def jinja():
    from jinja2 import Environment, FileSystemLoader, StrictUndefined
    env = Environment(loader=FileSystemLoader(str(ROOT)), undefined=StrictUndefined)
    env.filters['bool'] = lambda value: str(value).lower() in ('1', 'true', 'yes', 'on')
    return env


def fronted_config(provider, **extra):
    config = {
        'provider': provider, 'provider_workload': 'redirector', 'deployment_id': 'edge1',
        'deployment_type': 'fronted_c2_redirector', 'domain': 'lab.test',
        'redirector_subdomain': 'cdn', 'backend_ip': '192.0.2.10', 'operator_ip': '8.8.4.4',
        'fronting': True, 'fronting_endpoint_name': 'cdn-abc123',
        'fronting_origin_protocol': 'http',
    }
    config.update(extra)
    return config


class EdgeContractTests(unittest.TestCase):
    def setUp(self):
        self.driver = fake_cloud.DRIVER
        self.driver.__init__()

    def test_fronted_redirector_runs_through_the_fake_driver(self):
        adapter = SingleVmAdapter(self.driver, load_profile('redirector'))
        with tempfile.TemporaryDirectory() as temp:
            config = fronted_config('fakecloud', fakecloud_project='lab', fakecloud_state_dir=temp)
            infrastructure = adapter._infrastructure_config(config)
            self.assertEqual(infrastructure['fakecloud_edge'], {
                'host_header': 'cdn.lab.test', 'forwarding': 'HttpOnly', 'name': 'cdn-abc123'})
            self.assertEqual([(rule['port'], rule['source']) for rule in infrastructure['fakecloud_rules']],
                             [(80, 'fakecloud-edge'), (443, 'fakecloud-edge'), (4488, '*')])
            with mock.patch.object(Path, 'home', return_value=Path(temp)), \
                    mock.patch.object(deployment_engine, 'save_deployment_info'):
                self.assertTrue(adapter.deploy(config))
            self.assertEqual(config['edge_id'], 'fake-edge-edge1')
            self.assertEqual(config['edge_hostname'], 'cdn-abc123.edge.fakecloud.test')
            variables = self.driver.runs[0]['variables']
            self.assertEqual((variables['edge_id'], variables['edge_header'], variables['fronting']),
                             ('fake-edge-edge1', 'X-Fake-Edge-Id', True))

        plain = adapter._infrastructure_config(dict(fronted_config('fakecloud'), fronting=False,
                                                     fakecloud_project='lab'))
        self.assertIsNone(plain['fakecloud_edge'])
        self.assertEqual({rule['source'] for rule in plain['fakecloud_rules']}, {'*'})

    def test_drivers_without_an_edge_refuse_a_fronted_profile(self):
        adapter = SingleVmAdapter(self.driver, load_profile('redirector'))
        with mock.patch.object(type(self.driver), 'supports_edge', False), \
                self.assertRaisesRegex(ValueError, 'cannot front redirector'):
            adapter._infrastructure_config(fronted_config('fakecloud', fakecloud_project='lab'))

    def test_redirector_profile_validates_edge_inputs(self):
        profile = load_profile('redirector')
        for bad in ({'fronting_endpoint_name': 'Bad Name'}, {'fronting_origin_protocol': 'ftp'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                profile.validate(fronted_config('fakecloud', **bad))
        self.assertEqual(profile.edge(fronted_config('fakecloud', fronting_origin_protocol='https'))['forwarding'],
                         'HttpsOnly')
        self.assertIsNone(profile.edge({'fronting': False}))

    def test_azure_plans_front_door_and_locks_the_web_ports_to_it(self):
        driver = azure_cloud.azure_driver()
        adapter = SingleVmAdapter(driver, load_profile('redirector'))
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / '.ssh').mkdir()
            (Path(temp) / '.ssh' / 'c2deploy_edge1.pub').write_text(PUBLIC_KEY)
            with mock.patch.object(Path, 'home', return_value=Path(temp)):
                config = fronted_config(
                    'azure', azure_subscription_id='00000000-0000-0000-0000-000000000000')
                infrastructure = adapter._infrastructure_config(config)
                self.assertEqual([(rule['port'], rule['source']) for rule in infrastructure['azure_inbound_rules']],
                                 [(80, 'AzureFrontDoor.Backend'), (443, 'AzureFrontDoor.Backend'), (4488, '*')])
                normalized = azure_utils.validate_config(infrastructure)
                self.assertEqual(normalized['azure_edge'], infrastructure['azure_edge'])
                ids = azure_utils.resource_ids(normalized)
                self.assertTrue(ids['edge'].endswith('/providers/Microsoft.Cdn/profiles/c2itall-edge1-edge'))
                template = azure_utils.render_template(infrastructure)
                plain = azure_utils.render_template({k: v for k, v in infrastructure.items() if k != 'azure_edge'})
        types = [resource['type'] for resource in template['resources']]
        self.assertEqual(types[-5:], [
            'Microsoft.Cdn/profiles', 'Microsoft.Cdn/profiles/afdEndpoints',
            'Microsoft.Cdn/profiles/originGroups', 'Microsoft.Cdn/profiles/originGroups/origins',
            'Microsoft.Cdn/profiles/afdEndpoints/routes'])
        self.assertEqual(sorted(template['outputs']), ['edge_hostname', 'edge_id', 'private_ip', 'public_ip', 'vm_id'])
        route = template['resources'][-1]['properties']
        self.assertEqual((route['forwardingProtocol'], route['patternsToMatch']), ('HttpOnly', ['/*']))
        origin = template['resources'][-2]['properties']
        self.assertEqual(origin['originHostHeader'], 'cdn.lab.test')
        self.assertIn("publicIPAddresses', 'c2itall-edge1-ip'", origin['hostName'])
        self.assertNotIn('healthProbeSettings', template['resources'][-3]['properties'])
        sources = {rule['properties']['destinationPortRange']: rule['properties']['sourceAddressPrefix']
                   for rule in template['resources'][0]['properties']['securityRules']}
        self.assertEqual(sources['80'], 'AzureFrontDoor.Backend')
        self.assertEqual(sources['22'], '8.8.4.4/32')
        self.assertEqual(sorted(plain['outputs']), ['private_ip', 'public_ip', 'vm_id'])
        self.assertEqual(len(plain['resources']), 5)

        with self.assertRaisesRegex(ValueError, 'Invalid Azure edge request'):
            azure_utils.validate_config(dict(infrastructure, azure_edge={'name': 'x'}), require_key=False)

        state = dict(normalized, ownership_marker='m', planned_resource_ids=ids,
                     outputs={'edge_id': {'value': 'fd-id'}, 'edge_hostname': {'value': 'cdn-abc123-x.z01.azurefd.net'}})
        group = {'id': '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/c2itall-edge1',
                 'tags': azure_utils.ownership_tags(state)}
        resources = [{'id': ids['edge'], 'tags': azure_utils.ownership_tags(state)},
                     {'id': ids['edge'] + '/afdEndpoints/cdn-abc123', 'tags': {}}]
        azure_utils.validate_ownership(state, group, resources)
        with self.assertRaisesRegex(ValueError, 'unexpected resource'):
            azure_utils.validate_ownership(state, group, [{'id': ids['edge'] + '-other', 'tags': {}}])
        with mock.patch.object(azure_utils, 'load_state', return_value=state):
            self.assertEqual(driver.edge_endpoint('edge1', {}), {
                'edge_id': 'fd-id', 'edge_hostname': 'cdn-abc123-x.z01.azurefd.net',
                'edge_header': 'X-Azure-FDID'})

    def test_redirector_site_drops_requests_that_did_not_come_through_the_edge(self):
        env = jinja()
        base = dict(redirector_subdomain='cdn', domain='lab.test', redirector_cert='/c', redirector_key='/k',
                    c2_ip='192.0.2.10', havoc_https_port=9443, zero_logs=True, setup_integrated_tracker=False)
        site = 'modules/redirectors/templates/redirector-site-common.conf.j2'
        common = env.get_template(site).render(**base)
        self.assertIn('proxy_pass https://192.0.2.10:9443', common)
        self.assertEqual(common.count('{'), common.count('}'))
        plain = env.get_template('modules/redirectors/templates/redirector-site.conf.j2').render(**base)
        self.assertIn('return 301 https://$host$request_uri;', plain)
        self.assertNotIn('edge_ok', plain)
        self.assertEqual(plain.count('include snippets/redirector-site.conf;'), 1)
        fronted = env.get_template('modules/redirectors/templates/redirector-site.conf.j2').render(
            **base, edge_id='fd-id', edge_header='X-Azure-FDID', edge_hostname='x.z01.azurefd.net')
        self.assertIn('map $http_x_azure_fdid $edge_ok', fronted)
        self.assertIn('"fd-id" 1;', fronted)
        self.assertEqual(fronted.count('return 444;'), 2)
        self.assertEqual(fronted.count('include snippets/redirector-site.conf;'), 2)
        self.assertEqual(fronted.count('real_ip_header X-Forwarded-For;'), 2)


class StubModuleProfileTests(unittest.TestCase):
    def test_new_workloads_are_served_by_drivers_only(self):
        for workload in ('tracker', 'logging_server', 'share', 'hashtopolis'):
            with self.subTest(workload=workload):
                self.assertEqual(registry.providers_for(workload, legacy_fallback=True),
                                 ['aws', 'linode', 'flokinet', 'azure', 'local'])
                for provider in registry.PROVIDER_SPECS:
                    self.assertEqual(registry.provider_route_kind(provider, workload), 'native')
                self.assertTrue((ROOT / registry.WORKLOAD_SPECS[workload].entrypoint).is_file())

    def test_host_source_accepts_only_global_ipv4_hosts(self):
        self.assertEqual(host_source('8.8.4.4'), '8.8.4.4/32')
        for bad in ('10.0.0.1', '8.8.4.0/24', 'nope', '', '2001:db8::1'):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'global IPv4 host'):
                host_source(bad)

    def test_tracker_is_public_pixel_with_operator_dashboard(self):
        profile = load_profile('tracker')
        with self.assertRaises(ValueError):
            profile.validate({'operator_ip': '8.8.4.4'})
        self.assertEqual([(r['port'], r['source']) for r in profile.inbound_rules({'domain': 'lab.test'})],
                         [(80, '*'), (443, '*')])
        self.assertEqual(profile.service_variables({}, {}), {'tracker_subdomain': 'track', 'zero_logs': True})
        env = jinja()
        app = env.get_template('modules/tracker/templates/simple_email_tracker.py.j2').render(
            tracker_home='/opt/tracker', tracker_domain='track.lab.test', setup_integrated_tracker=False,
            tracker_bind='127.0.0.1')
        compile(app, 'tracker', 'exec')
        self.assertIn('{% for stat in stats %}', app)
        self.assertIn("app.run(host='127.0.0.1'", app)
        site = env.get_template('modules/tracker/templates/tracker-nginx.conf.j2').render(
            tracker_domain='track.lab.test', tracker_cert='/c', tracker_key='/k', operator_ip='8.8.4.4', zero_logs=True)
        self.assertIn('allow 8.8.4.4;', site)
        self.assertIn('location ~ ^/pixel/', site)
        unit = env.get_template('modules/tracker/templates/tracker.service.j2').render(tracker_home='/opt/tracker')
        self.assertIn('User=tracker', unit)
        self.assertNotIn('/root', unit)

    def test_logging_server_opens_ingest_only_to_named_hosts(self):
        profile = load_profile('logging_server')
        config = {'operator_ip': '8.8.4.4', 'logging_ingest_sources': ['1.1.1.1', '9.9.9.9']}
        profile.validate(config)
        self.assertEqual([(r['name'], r['port'], r['source']) for r in profile.inbound_rules(config)], [
            ('operator-https', 443, '8.8.4.4/32'), ('beats-1', 5044, '1.1.1.1/32'), ('beats-2', 5044, '9.9.9.9/32')])
        self.assertEqual([r['port'] for r in profile.inbound_rules({'operator_ip': '8.8.4.4'})], [443])
        self.assertEqual((profile.disk_gb(config), profile.service_timeout(config)), (64, 3600))
        for bad in ({'operator_ip': '8.8.4.4', 'logging_ingest_sources': ['10.1.1.1']},
                    {'operator_ip': '8.8.4.4', 'redelk_ref': 'bad ref'},
                    {'operator_ip': '8.8.4.4', 'logging_cert_name': 'Not A Host'},
                    {'operator_ip': '8.8.4.4', 'logging_ingest_sources': ['8.8.8.%d' % n for n in range(15)]}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                profile.validate(bad)
        certs = jinja().get_template('modules/logging-server/templates/redelk-certs.cnf.j2').render(
            logging_cert_name='logs.internal', logging_server_ip='8.8.8.8')
        for placeholder in ('MODIFYME', 'dnsnameofyourredelkserver', 'someseconddnsname', '123.123.123.123'):
            self.assertNotIn(placeholder, certs)
        self.assertIn('IP.1 = 8.8.8.8', certs)

    def test_hashtopolis_allows_operator_and_agents_only(self):
        profile = load_profile('hashtopolis')
        config = {'operator_ip': '8.8.4.4', 'hashtopolis_agent_sources': ['1.1.1.1'], 'domain': ''}
        profile.validate(config)
        self.assertEqual([(r['port'], r['source']) for r in profile.inbound_rules(config)],
                         [(443, '8.8.4.4/32'), (443, '1.1.1.1/32')])
        self.assertEqual([r['port'] for r in profile.inbound_rules(dict(config, domain='lab.test'))],
                         [443, 443, 80])
        with self.assertRaises(ValueError):
            profile.validate(dict(config, hashtopolis_admin_user='bad user'))
        site = jinja().get_template('modules/hashtopolis/templates/nginx-site.conf.j2').render(
            hashtopolis_host='8.8.8.8', hashtopolis_cert='/c', hashtopolis_key='/k',
            operator_ip='8.8.4.4', hashtopolis_agent_sources=['1.1.1.1'])
        self.assertIn('allow 1.1.1.1;', site)
        self.assertIn('proxy_pass http://127.0.0.1:8080;', site)
        compose = (ROOT / 'modules/hashtopolis/files/docker-compose.yml').read_text()
        self.assertNotIn('"8080:80"', compose)
        self.assertIn('127.0.0.1:8080:80', compose)

    def test_share_drive_has_no_public_web_ports(self):
        profile = load_profile('share')
        self.assertEqual(profile.kind, 'handoff')
        self.assertEqual([(r['port'], r['protocol']) for r in profile.inbound_rules({})], [(41641, 'Udp')])
        self.assertEqual(profile.disk_gb({'cloud_storage_gb': '50'}), 82)
        with self.assertRaises(ValueError):
            profile.validate({'cloud_storage_gb': '5000'})
        play = (ROOT / 'modules/share-drive/share_addons.yml').read_text()
        self.assertIn('interface: tailscale0', play)
        self.assertIn('trusted_domains 1', play)


class PayloadToolsTests(unittest.TestCase):
    def test_c2_records_resolve_to_an_ssh_target(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('payload_tools_test', ROOT / 'modules/tools/payload_tools.py')
        tools = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tools)
        records = [
            {'deployment_id': 'a', 'provider': 'azure', 'provider_workload': 'c2', 'c2_ip': '8.8.8.8'},
            {'deployment_id': 'b', 'provider': 'linode', 'deployment_type': 'c2_only'},
            {'deployment_id': 'c', 'provider': 'azure', 'provider_workload': 'redirector'},
        ]
        with mock.patch.object(tools, 'get_existing_deployments', return_value=records):
            self.assertEqual([record['deployment_id'] for record in tools.c2_deployments()], ['a', 'b'])
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / '.ssh' / 'c2deploy_a'
            key.parent.mkdir()
            key.write_text('key')
            with mock.patch.object(Path, 'home', return_value=Path(temp)):
                self.assertEqual(tools.ssh_target(records[0]), ('azureuser@8.8.8.8', str(key)))
                with self.assertRaisesRegex(ValueError, 'not found'):
                    tools.ssh_target(dict(records[1], c2_ip='8.8.8.9'))
        argv = tools.ssh_argv('azureuser@8.8.8.8', '/k', 'sudo -n ' + tools.GENERATOR)
        self.assertEqual(argv[-2:], ['azureuser@8.8.8.8', 'sudo -n /root/Tools/generate_havoc_payloads.sh'])
        self.assertIn('BatchMode=yes', argv)

    def test_menus_no_longer_advertise_construction(self):
        source = (ROOT / 'deploy.py').read_text()
        self.assertNotIn('UNDER-CONSTRUCTION', source)
        self.assertNotIn('coming soon', source)
        self.assertIn("deploy_logging_server()", source)
        self.assertIn("payload_tools_menu()", source)


if __name__ == '__main__':
    unittest.main()
