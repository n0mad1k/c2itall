"""Durable per-deployment state shared by every provider driver.

One JSON file per deployment records provisioning intent before any cloud
call, so a lost controller can always recover. The store owns the exclusive
lifecycle locks, the conflict rules for reusing a deployment ID, and the
archive of retired state. A driver supplies only its own validation and the
provider resource identities it plans to create.
"""

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import uuid

from .controller_io import regular_file, secure_directory

ID_PATTERN = re.compile(r'[a-z0-9][a-z0-9-]{0,39}')
_LOCKS = threading.local()


class StateStore:
    def __init__(self, validate, planned_ids, label='deployment'):
        self.validate = validate
        self.planned_ids = planned_ids
        self.label = label

    def path(self, deployment_id, state_dir):
        if not ID_PATTERN.fullmatch(deployment_id):
            raise ValueError('Invalid deployment ID')
        return Path(state_dir) / (deployment_id + '.json')

    def save(self, state, state_dir):
        path = self.path(state['deployment_id'], state_dir)
        with secure_directory(path.parent, create=True) as directory:
            temp = '.' + path.name + '.' + uuid.uuid4().hex
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, 'w') as stream:
                    json.dump(state, stream, indent=2)
                    stream.write('\n')
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, path.name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(temp, dir_fd=directory)
                except FileNotFoundError:
                    pass

    def load(self, deployment_id, state_dir):
        path = self.path(deployment_id, state_dir)
        with secure_directory(path.parent) as directory:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            with os.fdopen(fd) as stream:
                regular_file(stream.fileno())
                state = json.load(stream)
        if state.get('version') != 1 or state.get('deployment_id') != deployment_id:
            raise ValueError(f'Unsupported or mismatched {self.label} state')
        self.validate(state)
        if state.get('planned_resource_ids') != self.planned_ids(state):
            raise ValueError('State resource IDs do not match deployment identity')
        uuid.UUID(state['ownership_marker'])
        return state

    def list(self, state_dir):
        try:
            with secure_directory(state_dir) as directory:
                names = sorted(name for name in os.listdir(directory) if name.endswith('.json'))
        except FileNotFoundError:
            return []
        return [self.load(Path(name).stem, state_dir) for name in names]

    def prepare(self, validated, state_dir):
        """Persist intent for a validated plan, or return the identical existing intent."""
        path = self.path(validated['deployment_id'], state_dir)
        try:
            state = self.load(validated['deployment_id'], state_dir)
        except FileNotFoundError:
            state = None
        if state is not None:
            if any(state.get(k) != v for k, v in validated.items()):
                raise ValueError('Existing state conflicts with requested configuration')
            return state
        with secure_directory(path.parent / 'archive', create=True) as archive:
            try:
                os.stat(path.name, dir_fd=archive, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('Deployment ID already archived; use a new deployment ID')
        if validated['ssh_key_generated'] and any(Path(validated[k]).exists()
                                                 for k in ('ssh_key_path', 'ssh_private_key_path')):
            raise ValueError('Persist deployment intent before generating keys; existing keys are user-owned')
        state = dict(validated, version=1, status='planned', ownership_marker=str(uuid.uuid4()),
                     planned_resource_ids=self.planned_ids(validated), actual_resource_ids=[])
        self.save(state, state_dir)
        return state

    def retire(self, state, state_dir):
        """Remove generated keys, mark the state deleted and move it to the archive."""
        path = self.path(state['deployment_id'], state_dir)
        with secure_directory(path.parent) as parent, \
                secure_directory(path.parent / 'archive', create=True) as archive:
            if state['ssh_key_generated']:
                with secure_directory(Path(state['ssh_private_key_path']).parent) as keys:
                    for key in ('ssh_private_key_path', 'ssh_key_path'):
                        try:
                            os.unlink(Path(state[key]).name, dir_fd=keys)
                        except FileNotFoundError:
                            pass
            state['status'] = 'deleted'
            self.save(state, state_dir)
            os.replace(path.name, path.name, src_dir_fd=parent, dst_dir_fd=archive)
            os.fsync(parent)
            os.fsync(archive)

    @contextlib.contextmanager
    def lock(self, deployment_id, target, state_dir):
        """Serialize both the deployment identity and its provider-side target."""
        path = self.path(deployment_id, state_dir)
        names = [f'.deployment-{deployment_id}.lock',
                 '.group-' + hashlib.sha256(str(target).lower().encode()).hexdigest() + '.lock']
        held = getattr(_LOCKS, 'held', None)
        if held is None:
            held = _LOCKS.held = set()
        acquired = []
        try:
            with secure_directory(path.parent, create=True) as directory:
                for name in names:
                    identity = (str(path.parent.absolute()), name)
                    if identity in held:
                        continue
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                    try:
                        regular_file(fd)
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BaseException:
                        os.close(fd)
                        raise
                    held.add(identity)
                    acquired.append((identity, fd))
                yield
        finally:
            for identity, fd in reversed(acquired):
                held.remove(identity)
                os.close(fd)
