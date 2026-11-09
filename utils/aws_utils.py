"""AWS controller credentials: Infisical first, then the environment."""

import logging
import os
import subprocess

INFISICAL_FOLDER = 'aws'


def load_aws_credentials():
    """Load AWS keys from Infisical, then the environment."""
    key = secret = ''
    creds = os.path.expanduser('~/.local/bin/creds')
    try:
        key = subprocess.check_output(
            [creds, 'get', 'AWS_ACCESS_KEY', INFISICAL_FOLDER],
            text=True, stderr=subprocess.DEVNULL).strip()
        secret = subprocess.check_output(
            [creds, 'get', 'AWS_SECRET_KEY', INFISICAL_FOLDER],
            text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        key = secret = ''
    if not (key and secret):
        key = os.environ.get('AWS_ACCESS_KEY_ID', '')
        secret = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
    return {'aws_access_key': key, 'aws_secret_key': secret}


def prepare_aws_environment(config, teardown=False):
    """Export the controller credentials; load them when the config lacks them."""
    if not (config.get('aws_access_key') and config.get('aws_secret_key')):
        loaded = load_aws_credentials()
        if loaded['aws_access_key'] and loaded['aws_secret_key']:
            config.update(loaded)
        else:
            logging.warning('AWS credentials were not found in Infisical or the environment')
    if config.get('aws_access_key'):
        os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
    if config.get('aws_secret_key'):
        os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
    if not teardown and config.get('aws_region'):
        os.environ['AWS_DEFAULT_REGION'] = config['aws_region']
