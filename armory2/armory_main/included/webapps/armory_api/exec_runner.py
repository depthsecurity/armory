"""
Shell command execution backend for the Armory REST API.

Runs raw shell commands on the host that `armory-web` runs on, so an MCP client
can proxy tooling (nmap, curl, smbclient, …) through Armory instead of needing
its own shell on that host. Commands can run synchronously — the request blocks
until the command exits or its timeout expires — or in the background, in which
case a job ID is returned and the caller polls for output.

Every job lives in this module's in-memory registry; nothing is written to the
database and the registry is emptied when armory-web restarts. Each job is run
in its own session (setsid), so killing a job kills the whole process tree it
spawned rather than just the shell.

This is a remote code execution facility by design. `views.py` gates it behind
the API key, the ARMORY_API_EXEC_ENABLED setting, and a refusal to run at all
when the API key is still the public built-in default.
"""

import os
import signal
import subprocess
import threading
import time
from collections import OrderedDict
from datetime import datetime

# Defaults and hard ceilings applied to every job.
DEFAULT_TIMEOUT = 60          # seconds a command may run before it is killed
MAX_TIMEOUT = 3600            # ceiling a caller may request
DEFAULT_MAX_OUTPUT = 1000000  # bytes retained per stream; the rest is dropped
MAX_JOBS = 200                # completed jobs kept before the oldest are pruned
KILL_GRACE = 3                # seconds between SIGTERM and SIGKILL

# Terminal states — anything else means the job is still running.
DONE_STATES = ('finished', 'timed_out', 'killed', 'failed')

_jobs = OrderedDict()
_jobs_lock = threading.Lock()


class _Buffer:
    """Thread-safe append-only text buffer with a byte ceiling.

    Output past the ceiling is discarded, but the running total is kept so the
    caller can tell how much was produced.
    """

    def __init__(self, limit=DEFAULT_MAX_OUTPUT):
        self._limit = limit
        self._chunks = []
        self._kept = 0
        self._total = 0
        self._lock = threading.Lock()

    def append(self, text):
        if not text:
            return
        size = len(text.encode('utf-8', 'replace'))
        with self._lock:
            self._total += size
            room = self._limit - self._kept
            if room <= 0:
                return
            if size > room:
                text = text[:room]
                size = len(text.encode('utf-8', 'replace'))
            self._chunks.append(text)
            self._kept += size

    def value(self):
        with self._lock:
            return ''.join(self._chunks), self._total > self._kept, self._total


def _now_iso():
    return datetime.now().isoformat(timespec='seconds')


def _shell_path():
    for candidate in ('/bin/bash', '/usr/bin/bash', '/bin/sh'):
        if os.path.exists(candidate):
            return candidate
    return None


def _terminate(proc):
    """SIGTERM the job's process group, then SIGKILL anything still alive."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            return
        try:
            proc.wait(timeout=KILL_GRACE)
            return
        except subprocess.TimeoutExpired:
            continue


def _pump(stream, buffer):
    try:
        for line in stream:
            buffer.append(line)
    except (ValueError, OSError):
        pass
    finally:
        try:
            stream.close()
        except (ValueError, OSError):
            pass


def _prune_locked():
    """Drop the oldest completed jobs once the registry exceeds MAX_JOBS."""
    if len(_jobs) <= MAX_JOBS:
        return
    for job_id in [j for j, rec in _jobs.items() if rec['status'] in DONE_STATES]:
        if len(_jobs) <= MAX_JOBS:
            break
        del _jobs[job_id]


def _new_job(command, cwd, timeout, env, background):
    with _jobs_lock:
        job_id = f"cmd-{len(_jobs) + 1}-{int(time.time() * 1000) % 1000000}"
        job = {
            'id': job_id,
            'command': command,
            'cwd': cwd or os.getcwd(),
            'timeout': timeout,
            'background': background,
            'env_keys': sorted(env.keys()) if env else [],
            'status': 'running',
            'pid': None,
            'returncode': None,
            'error': None,
            'started_at': _now_iso(),
            'finished_at': None,
            'duration': None,
            '_start': time.monotonic(),
            '_stdout': _Buffer(),
            '_stderr': _Buffer(),
            '_proc': None,
            '_kill_requested': False,
            '_done': threading.Event(),
        }
        _jobs[job_id] = job
        _prune_locked()
    return job


def _execute(job, env):
    """Run the job's command to completion, filling in its result fields."""
    command = job['command']
    cwd = job['cwd']
    full_env = {**os.environ, 'PYTHONUNBUFFERED': '1'}
    if env:
        full_env.update({str(k): str(v) for k, v in env.items()})

    try:
        proc = subprocess.Popen(
            command,
            shell=True,
            executable=_shell_path(),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=full_env,
            text=True,
            errors='replace',
            bufsize=1,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        job['status'] = 'failed'
        job['error'] = str(exc)
        job['finished_at'] = _now_iso()
        job['duration'] = round(time.monotonic() - job['_start'], 3)
        job['_done'].set()
        return

    job['_proc'] = proc
    job['pid'] = proc.pid

    pumps = [
        threading.Thread(target=_pump, args=(proc.stdout, job['_stdout']), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, job['_stderr']), daemon=True),
    ]
    for t in pumps:
        t.start()

    deadline = job['_start'] + job['timeout']
    status = 'finished'
    while True:
        try:
            proc.wait(timeout=0.2)
            # A kill request that landed while we were waiting reaps the process
            # here rather than in the branch below, so label it from the signal.
            if job['_kill_requested'] and (proc.returncode or 0) < 0:
                status = 'killed'
            break
        except subprocess.TimeoutExpired:
            if job['_kill_requested']:
                status = 'killed'
                _terminate(proc)
                break
            if time.monotonic() >= deadline:
                status = 'timed_out'
                _terminate(proc)
                break

    for t in pumps:
        t.join(timeout=2)

    job['returncode'] = proc.returncode
    job['status'] = status
    if status == 'timed_out':
        job['error'] = f"Command exceeded its {job['timeout']}s timeout and was killed"
    elif status == 'killed':
        job['error'] = 'Command was killed by a kill request'
    job['finished_at'] = _now_iso()
    job['duration'] = round(time.monotonic() - job['_start'], 3)
    job['_done'].set()


def serialize(job, include_output=True, tail=0):
    """JSON-safe view of a job. `tail` returns only the last N chars per stream."""
    out = {
        'id': job['id'],
        'command': job['command'],
        'cwd': job['cwd'],
        'status': job['status'],
        'running': job['status'] not in DONE_STATES,
        'pid': job['pid'],
        'returncode': job['returncode'],
        'timeout': job['timeout'],
        'background': job['background'],
        'started_at': job['started_at'],
        'finished_at': job['finished_at'],
        'duration': job['duration'],
        'error': job['error'],
    }
    if job['env_keys']:
        out['env_keys'] = job['env_keys']

    if not include_output:
        return out

    for name, key in (('stdout', '_stdout'), ('stderr', '_stderr')):
        text, truncated, total = job[key].value()
        if tail and len(text) > tail:
            text = text[-tail:]
            truncated = True
        out[name] = text
        out[f'{name}_truncated'] = truncated
        out[f'{name}_bytes'] = total
    return out


def run(command, cwd=None, timeout=DEFAULT_TIMEOUT, env=None, background=False):
    """Start a command. Blocks until it exits unless background is True."""
    job = _new_job(command, cwd, timeout, env, background)

    if background:
        threading.Thread(target=_execute, args=(job, env), daemon=True).start()
        # Give the shell a beat to start so the caller usually gets a pid back.
        job['_done'].wait(timeout=0.25)
    else:
        _execute(job, env)

    return job


def get(job_id):
    with _jobs_lock:
        return _jobs.get(job_id)


def wait(job, timeout):
    """Block until the job finishes or `timeout` seconds pass. Returns the job."""
    job['_done'].wait(timeout=timeout)
    return job


def all_jobs(status=None, search=None):
    """Newest first, optionally filtered by status or a substring of the command."""
    with _jobs_lock:
        jobs = list(_jobs.values())
    jobs.reverse()
    if status == 'running':
        jobs = [j for j in jobs if j['status'] not in DONE_STATES]
    elif status:
        jobs = [j for j in jobs if j['status'] == status]
    if search:
        needle = search.lower()
        jobs = [j for j in jobs if needle in j['command'].lower()]
    return jobs


def kill(job):
    """Request that a running job's process tree be killed. Returns True if it was running."""
    if job['status'] in DONE_STATES:
        return False
    job['_kill_requested'] = True
    proc = job['_proc']
    if proc is not None:
        _terminate(proc)
    job['_done'].wait(timeout=KILL_GRACE * 2 + 1)
    return True
