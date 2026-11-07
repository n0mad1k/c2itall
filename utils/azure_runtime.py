"""Azure controller runtime loaded through provider registry metadata."""

import json
import logging
import os
from pathlib import Path
import tempfile
import time

from . import azure_utils
from .provider_registry import ProviderRuntime


class AzureControllerRuntime(ProviderRuntime):
    """Run Azure's allowlisted localhost playbooks with isolated variables."""

    def create_extra_vars(self, config):
        allowed = azure_utils.CONFIG_KEYS | {
            'ownership_marker', 'azure_template_file'}
        return json.dumps({key: value for key, value in config.items()
                           if key in allowed and value is not None})

    def execute_playbook(self, playbook, config, output_filter):
        expected = {
            str(azure_utils.ROOT / 'providers/Azure/infrastructure.yml'),
            str(azure_utils.ROOT / 'providers/Azure/cleanup.yml'),
        }
        resolved = str(Path(playbook).resolve())
        if resolved not in expected:
            raise ValueError(
                'Azure may execute only its infrastructure and cleanup playbooks')
        deadline = config.get(
            'azure_deadline', time.monotonic() + 1800)
        logs = Path(config.get('azure_state_dir') or
                    azure_utils.STATE_DIR) / 'logs'
        try:
            with azure_utils.secure_directory(logs, create=True):
                pass
            with tempfile.TemporaryDirectory(
                    prefix='c2itall-azure-') as temporary:
                runtime = dict(config)
                if Path(resolved).name == 'infrastructure.yml':
                    template = Path(temporary) / 'infrastructure.json'
                    template.write_text(json.dumps(
                        azure_utils.render_template(config)))
                    template.chmod(0o600)
                    runtime['azure_template_file'] = str(template)
                variables = Path(temporary) / 'variables.json'
                variables.write_text(self.create_extra_vars(runtime))
                variables.chmod(0o600)
                result = azure_utils.run_command([
                    'ansible-playbook', resolved, '-i', 'localhost,',
                    '--extra-vars', '@' + str(variables),
                ], timeout=180, deadline=deadline)
            log_path = logs / (config['deployment_id'] + '.log')
            with azure_utils.secure_directory(logs) as directory:
                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
                if hasattr(os, 'O_NOFOLLOW'):
                    flags |= os.O_NOFOLLOW
                fd = os.open(log_path.name, flags, 0o600, dir_fd=directory)
                with os.fdopen(fd, 'a') as stream:
                    azure_utils._regular_file(stream.fileno())
                    stream.write(result.stdout + result.stderr)
            for line in result.stdout.splitlines():
                if output_filter(line):
                    print(line)
            return True
        except Exception as exc:
            logging.error('Azure playbook execution failed: %s', exc)
            return False


def azure_runtime():
    return AzureControllerRuntime()
