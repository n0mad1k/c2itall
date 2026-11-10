"""Lab-mode configs for the red-side workloads; the plays stay provider-neutral.

Each builder collects a lab member's config and deploys it. Nothing here
names a provider: the lab record decides addresses and the registry decides
which provider may host the workload.
"""

import importlib.util
import os
import re
import secrets
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils import lab as lab_mod
from utils.common import COLORS, confirm_action, generate_deployment_id
from utils.controller_io import ROOT
from utils.provider_utils import apply_provider_profile, gather_provider_config, select_provider

LAB_DOMAIN = 'lab.internal'
OPERATOR_NAME = re.compile(r'[A-Za-z0-9_-]{1,32}')


def member_config(lab, workload, **extra):
    """The provider half of a lab member's config; every member shares the lab SSH key."""
    config = {'deployment_id': generate_deployment_id(), 'lab': lab['name']}
    print(f"Deployment ID: {COLORS['CYAN']}{config['deployment_id']}{COLORS['RESET']}")
    provider = select_provider(workload)
    if not provider:
        return None
    provider_config = gather_provider_config(provider, workload)
    if not provider_config:
        return None
    config.update(provider_config)
    config.update(provider=provider, provider_workload=workload,
                  ssh_key_path=lab['ssh_key_path'], ssh_after_deploy=False, **extra)
    return config


def lab_cidrs(lab):
    return list(lab['cidrs']) + list(lab['range_cidrs'])


def member_ips(lab, *workloads):
    return [entry['lab_ip'] for entry in lab['members'].values()
            if entry.get('status') == 'ready' and entry.get('workload') in workloads]


def deploy(config, label):
    print(f"\n{COLORS['CYAN']}Deployment Summary:{COLORS['RESET']}")
    for key in ('deployment_id', 'lab', 'provider'):
        print(f"{key}: {config[key]}")
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with the {label} deployment?{COLORS['RESET']}",
                          default=False):
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        return False
    from utils.deployment_engine import deploy_infrastructure
    success = deploy_infrastructure(config)
    colour = COLORS['GREEN'] if success else COLORS['RED']
    print(f"\n{colour}{label} deployment {'complete' if success else 'failed'}.{COLORS['RESET']}")
    return success


def c2(lab):
    """Havoc on the lab address with named operators; no redirector, mail or certificate."""
    config = member_config(lab, 'c2', deployment_type='c2_only', c2_only=True, domain=LAB_DOMAIN,
                           c2_subdomain='c2', c2_framework='havoc', zero_logs=False,
                           letsencrypt_email='lab@' + LAB_DOMAIN)
    if config is None:
        return False
    names = [name.strip() for name in input('Havoc operator names, comma separated [red1]: ').split(',')
             if name.strip()] or ['red1']
    if any(not OPERATOR_NAME.fullmatch(name) for name in names):
        print(f"{COLORS['RED']}Operator names: letters, digits, _ and - only{COLORS['RESET']}")
        return False
    operators = lab_mod.read_secret(lab, 'c2-operators.json') or {}
    for name in ['admin', *names]:
        operators.setdefault(name, secrets.token_urlsafe(18))
    lab_mod.write_secret(lab, 'c2-operators.json', operators)
    config.update(c2_name='c2-' + config['deployment_id'],
                  havoc_admin_user='admin', havoc_admin_password=operators['admin'],
                  havoc_operators=[{'name': name, 'password': password}
                                   for name, password in operators.items() if name != 'admin'])
    success = deploy(config, 'C2')
    if success:
        print('Operator credentials: ' + str(lab_mod.secret_dir(lab) / 'c2-operators.json'))
    return success


def payload_server(lab):
    config = member_config(lab, 'payload_server', deployment_type='secure_payload_server',
                           domain=LAB_DOMAIN, payload_subdomain='payloads',
                           letsencrypt_email='lab@' + LAB_DOMAIN, host_executables=True,
                           host_scripts=True, host_documents=True, host_mobile=False,
                           enable_basic_auth=False, enable_ip_filtering=True,
                           allowed_ips=lab_cidrs(lab), enable_user_agent_filtering=False,
                           enable_rate_limiting=False, auto_generate_payloads=False)
    if config is None:
        return False
    config['payload_server_name'] = 'payloads-' + config['deployment_id']
    return deploy(config, 'payload server')


def attack_box(lab):
    config = member_config(lab, 'attack_box', deployment_type='kali_attack_box',
                           attack_box_type='kali', setup_domain=False, setup_vpn=False,
                           setup_tor=False, custom_wordlists=False, enhanced_opsec=False,
                           work_dir='/root/operator', tool_name='trashpanda',
                           project_name='operator', auto_teardown_on_fail=False)
    if config is None:
        return False
    config['attack_box_name'] = 'kali-' + config['deployment_id']
    apply_provider_profile(config, 'instance_size', 'medium')
    return deploy(config, 'attack box')


def logging_server(lab):
    config = member_config(lab, 'logging_server', deployment_type='logging_server',
                           logging_ingest_sources=member_ips(lab, 'c2', 'payload_server'),
                           logging_cert_name='logs.internal', redelk_ref='master')
    if config is None:
        return False
    config['logging_server_name'] = 'logs-' + config['deployment_id']
    return deploy(config, 'logging server')


def chat(lab):
    """Matrix through Phantom under a lab-only name; the lab overlay replaces Tailscale."""
    config = member_config(lab, 'chat', server_type='matrix', domain='chat.internal',
                           tailscale_auth_key='', enable_bot_support=False)
    if config is None:
        return False
    path = ROOT / 'modules' / 'chat-server' / 'deploy_chat.py'
    spec = importlib.util.spec_from_file_location('deploy_chat', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = module._load_matrix_config().gather_config(config)
    if config is None:
        return False
    if not confirm_action(f"\n{COLORS['YELLOW']}Proceed with the chat deployment?{COLORS['RESET']}",
                          default=False):
        return False
    return bool(module.deploy_chat(config))
