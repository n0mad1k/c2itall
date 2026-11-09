"""Linode controller token: the config, then Infisical."""

import logging
import os
import subprocess


def prepare_linode_environment(config, teardown=False):
    """Export the Linode token for the controller; load it when the config lacks it."""
    token = config.get('linode_token', '')
    if not token:
        try:
            token = subprocess.check_output(
                [os.path.expanduser('~/.local/bin/creds'), 'get',
                 'LINODE_TOKEN', 'homelab'],
                text=True, stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            logging.warning('Failed to load Linode token from Infisical: %s', exc)
    if token:
        os.environ['LINODE_TOKEN'] = token
        config['linode_token'] = token
