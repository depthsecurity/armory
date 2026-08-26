#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from importlib import resources
if os.getenv("ARMORY_HOME"):
    CONFIG_FOLDER = os.getenv("ARMORY_HOME")
else:
    CONFIG_FOLDER = os.path.join(os.getenv("HOME"), ".armory")

if os.getenv("ARMORY_CONFIG"):
    CONFIG_FILE = os.getenv("ARMORY_CONFIG")
else:
    CONFIG_FILE = "settings.py"

if not os.path.exists(CONFIG_FOLDER):
    os.mkdir(CONFIG_FOLDER)
if not os.path.exists(os.path.join(CONFIG_FOLDER, CONFIG_FILE)):
    with open(os.path.join(CONFIG_FOLDER, CONFIG_FILE), "w") as out:
        
        out.write(
            resources.read_text(
                "armory2.default_configs", "settings.py"
            )
        )    


def main(or_args=""):
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'armory2.armory2.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    if or_args and len(or_args) > 1:
        execute_from_command_line(or_args)
    else:
        execute_from_command_line(sys.argv)


def web():
    import argparse
    import signal
    import subprocess

    parser = argparse.ArgumentParser(
        prog='armory-web',
        description='Start the Armory web server.',
    )
    parser.add_argument(
        '-b', '--bind',
        default='127.0.0.1',
        help='IP address to listen on (default: 127.0.0.1)',
    )
    parser.add_argument(
        '-p', '--port',
        default='8099',
        help='Port to listen on (default: 8099)',
    )
    parser.add_argument(
        '--mcp',
        action='store_true',
        help='Also start the Armory MCP server over streamable-http',
    )
    parser.add_argument(
        '--mcp-port',
        default='8100',
        help='Port for the MCP server when --mcp is given (default: 8100)',
    )
    args = parser.parse_args()

    env = os.environ.copy()
    env['ARMORY_WEB_BIND'] = args.bind
    env['ARMORY_WEB_PORT'] = str(args.port)

    children = []

    if args.mcp:
        # The MCP server is an HTTP client of the armory_api webapp, so point it
        # at whatever address daphne is about to bind. It runs as a child
        # process rather than mounted into the ASGI app because daphne does not
        # implement the ASGI lifespan protocol, which FastMCP's streamable-http
        # app needs in order to start its session manager.
        api_host = '127.0.0.1' if args.bind == '0.0.0.0' else args.bind
        children.append(subprocess.Popen([
            sys.executable, '-m', 'armory2.armory_main.included.mcp.server',
            '--url', f'http://{api_host}:{args.port}',
            '--transport', 'streamable-http',
            '--host', args.bind,
            '--port', str(args.mcp_port),
        ], env=env))
        print(
            f'Armory MCP server listening on '
            f'http://{api_host}:{args.mcp_port}/mcp'
        )

    web_proc = subprocess.Popen([
        sys.executable, '-m', 'daphne',
        '-b', args.bind,
        '-p', str(args.port),
        'armory2.armory2.asgi:application',
    ], env=env)
    children.append(web_proc)

    def _stop_children(*_):
        for proc in children:
            if proc.poll() is None:
                proc.terminate()

    # Ctrl-C in a terminal signals the whole process group, but a bare
    # SIGINT/SIGTERM aimed at this process alone would otherwise orphan the
    # children, leaving their ports bound.
    signal.signal(signal.SIGINT, _stop_children)
    signal.signal(signal.SIGTERM, _stop_children)

    try:
        web_proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        _stop_children()
        for proc in children:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    sys.exit(web_proc.returncode or 0)

def init():
    main(["manage", "migrate"])

def docker():
    args = sys.argv[1:]
    
    main(["manage", "build_docker"] + args)

if __name__ == '__main__':
    main()
