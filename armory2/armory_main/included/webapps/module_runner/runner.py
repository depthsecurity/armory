import os
import re
import signal
import subprocess
import threading
import uuid

# Structured output markers emitted by ModuleTemplate.run_cmd when
# ARMORY_STRUCTURED_OUTPUT=1 is set in the environment.
#   __ARMORY:S:{proc_id}:{cmd}   — subprocess start
#   __ARMORY:P:{proc_id}:{pid}   — subprocess OS pid
#   __ARMORY:L:{proc_id}:{line}  — one line of subprocess stdout
#   __ARMORY:E:{proc_id}:{rc}    — subprocess exit
_START_RE = re.compile(r'^__ARMORY:S:([0-9a-f]+):(.+)$')
_PID_RE   = re.compile(r'^__ARMORY:P:([0-9a-f]+):(\d+)$')
_LINE_RE  = re.compile(r'^__ARMORY:L:([0-9a-f]+):(.*)$')
_END_RE   = re.compile(r'^__ARMORY:E:([0-9a-f]+):(-?\d+)$')

# {(run_id, proc_index): os_pid}  — populated while a subprocess is live
_active_pids: dict = {}
_pids_lock = threading.Lock()


def kill_proc(run_id: str, proc_index: int) -> None:
    with _pids_lock:
        pid = _active_pids.get((run_id, proc_index))
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def _stream(run_id, module_name, args):
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()
    group = f'run_{run_id.replace("-", "_")}'

    def send(msg):
        try:
            async_to_sync(channel_layer.group_send)(group, {'type': 'run.output', 'message': msg})
        except Exception:
            pass

    cmd = ['armory', '--quiet', '-m', module_name] + args
    env = {**os.environ, 'PYTHONUNBUFFERED': '1', 'ARMORY_STRUCTURED_OUTPUT': '1'}

    send({'type': 'run.start', 'module': module_name, 'args': args})

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
            bufsize=1,
        )

        # Maps the 16-hex proc_id from ModuleTemplate markers to a
        # sequential integer index used by the frontend window system.
        proc_map = {}
        proc_counter = 0

        for raw in proc.stdout:
            line = raw.rstrip('\n')

            m = _START_RE.match(line)
            if m:
                pid, cmd_str = m.group(1), m.group(2)
                idx = proc_counter
                proc_map[pid] = idx
                proc_counter += 1
                send({'type': 'proc.start', 'proc_index': idx, 'cmd': cmd_str})
                continue

            m = _PID_RE.match(line)
            if m:
                pid, os_pid = m.group(1), int(m.group(2))
                idx = proc_map.get(pid, -1)
                if idx >= 0:
                    with _pids_lock:
                        _active_pids[(run_id, idx)] = os_pid
                continue

            m = _LINE_RE.match(line)
            if m:
                pid, content = m.group(1), m.group(2)
                send({'type': 'proc.output', 'proc_index': proc_map.get(pid, -1), 'line': content})
                continue

            m = _END_RE.match(line)
            if m:
                pid, rc = m.group(1), int(m.group(2))
                idx = proc_map.get(pid, -1)
                with _pids_lock:
                    _active_pids.pop((run_id, idx), None)
                send({'type': 'proc.end', 'proc_index': idx, 'returncode': rc})
                continue

            # Unstructured line — Armory main-process output (display() calls,
            # "Processing results…", error messages, etc.)
            send({'type': 'proc.output', 'proc_index': -1, 'line': line})

        proc.wait()
        # Clean up any remaining pids for this run
        with _pids_lock:
            for key in [k for k in _active_pids if k[0] == run_id]:
                del _active_pids[key]
        send({'type': 'run.end', 'returncode': proc.returncode})

    except FileNotFoundError:
        send({'type': 'run.error', 'message': 'armory command not found — is it installed in this environment?'})
        send({'type': 'run.end', 'returncode': 1})
    except Exception as exc:
        send({'type': 'run.error', 'message': str(exc)})
        send({'type': 'run.end', 'returncode': 1})


def start_run(run_id: str, module_name: str, args: list) -> None:
    t = threading.Thread(target=_stream, args=(run_id, module_name, args), daemon=True)
    t.start()
