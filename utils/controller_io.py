"""Bounded controller processes and symlink-safe file handling.

Every provider driver runs its cloud tooling and writes its durable state
through these helpers, so a new provider inherits the same process and
filesystem discipline without re-implementing it.
"""

import contextlib
import os
from pathlib import Path
import signal
import stat
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


@contextlib.contextmanager
def secure_directory(path, create=False):
    """Open each ancestor without following symlinks, retaining a stable dir FD."""
    path = Path(path).absolute()
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if part in ('.', '..'):
                raise ValueError('Unsafe directory component')
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=directory)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        yield directory
    finally:
        os.close(directory)


def regular_file(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        raise ValueError('Expected an owned regular file with no hard links')


@contextlib.contextmanager
def interruption_handlers():
    """Make both interactive interrupts and termination stop child groups."""
    previous = {}
    if threading.current_thread() is threading.main_thread():
        def interrupted(signum, frame):
            raise KeyboardInterrupt(f'Interrupted by signal {signum}')
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, interrupted)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def run_command(argv, timeout=60, deadline=None, check=True, env=None, label='Controller'):
    """Run a bounded controller command and reap its entire process group."""
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
    if timeout <= 0:
        raise TimeoutError(f'{label} lifecycle deadline exceeded')
    with interruption_handlers():
        process = subprocess.Popen(argv, cwd=ROOT, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.stdout.close()
                process.stderr.close()
            raise
    result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    if result.returncode and check:
        raise RuntimeError(f'{label} command failed ({result.returncode}): {(stderr or stdout).strip()}')
    return result
