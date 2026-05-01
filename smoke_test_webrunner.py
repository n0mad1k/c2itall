#!/usr/bin/env python3
"""
WEBRUNNER smoke test — 1 nanode, masscan-only, operator IP /32, port 22, auto-teardown.
Run from c2itall root: python3 smoke_test_webrunner.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from utils.common import generate_deployment_id, setup_logging
from utils.ssh_utils import generate_ssh_key
from utils.deployment_engine import execute_playbook, set_provider_environment

OPERATOR_IP = "129.222.0.125"
TARGET_CIDR = f"{OPERATOR_IP}/32"

config = {}
config['deployment_id'] = generate_deployment_id()
config['engagement'] = 'smoketest'
config['deployment_type'] = 'webrunner'
config['webrunner_deployment'] = True
config['webrunner_name'] = f"wr-smoke-{config['deployment_id']}"

# Provider — cheapest Linode nanode
config['providers'] = ['linode']
config['provider'] = 'linode'
config['linode_region'] = 'us-east'
config['linode_instance_type'] = 'g6-nanode-1'
config['linode_image'] = 'linode/debian12'

# Scan — masscan-only, single port, operator /32
config['scan_mode'] = 'masscan-only'
config['ports'] = [22]
config['ports_str'] = '22'
config['masscan_rate'] = 1000
config['use_tor'] = False
config['targets_file'] = ''
config['total_ips'] = 1
config['preset'] = 'sprint'
config['chunk_size'] = 500_000

# OPSEC
config['operator_ip'] = OPERATOR_IP
config['enhanced_opsec'] = False
config['teardown_after_scan'] = True

# SSH key
ssh_key_path = generate_ssh_key(config['webrunner_name'])
if not ssh_key_path:
    sys.exit('Failed to generate SSH key')
config['ssh_key_path'] = f"{ssh_key_path}.pub"
config['ssh_key_name'] = os.path.basename(ssh_key_path)

# Single node chunk targeting operator IP
node_chunks = [{
    'idx': 0,
    'node_name': f"{config['webrunner_name']}-01",
    'provider': 'linode',
    'cidrs': [TARGET_CIDR],
    'ip_count': 1,
}]

logs_dir = os.path.abspath('logs')
os.makedirs(logs_dir, exist_ok=True)
chunks_file = os.path.join(logs_dir, f"node_chunks_{config['deployment_id']}.json")
with open(chunks_file, 'w') as f:
    json.dump(node_chunks, f)

config['node_chunks_file'] = chunks_file
config['scanner_ip_log'] = os.path.join(logs_dir, f"scanner_ips_{config['webrunner_name']}.txt")
config['results_dir'] = os.path.join(logs_dir, f"webrunner_{config['deployment_id']}")

log_file = setup_logging(config['deployment_id'], 'webrunner_smoketest')

print(f"\n[*] WEBRUNNER smoke test")
print(f"    ID:     {config['deployment_id']}")
print(f"    Target: {TARGET_CIDR} (operator IP)")
print(f"    Mode:   masscan-only, port 22")
print(f"    Node:   g6-nanode-1 @ us-east (auto-teardown)\n")

set_provider_environment({**config, 'provider': 'linode'})

success = execute_playbook('providers/webrunner.yml', config)
sys.exit(0 if success else 1)
