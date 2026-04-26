#!/usr/bin/env python3
"""
PyForensix Web Server
=====================
Run:
  python server.py                  # http://localhost:5000
  python server.py --port 8080
  python server.py --host 0.0.0.0   # Expose on LAN (be careful)
  python server.py --debug
"""
import argparse
import sys
import os
import platform


def print_banner():
    print(r"""
 ██████╗ ██╗   ██╗███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██╗  ██╗
 ██╔══██╗╚██╗ ██╔╝██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║╚██╗██╔╝
 ██████╔╝ ╚████╔╝ █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║ ╚███╔╝
 ██╔═══╝   ╚██╔╝  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║ ██╔██╗
 ██║        ██║   ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██╔╝ ██╗
 ╚═╝        ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝
    Web Threat Dashboard — Flask + SocketIO
""")


def main():
    parser = argparse.ArgumentParser(description='PyForensix Web Server')
    parser.add_argument('--host',  default='127.0.0.1', help='Bind host (default: 127.0.0.1)')
    parser.add_argument('--port',  type=int, default=5000, help='Port (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable Flask debug mode')
    args = parser.parse_args()

    print_banner()

    # Check dependencies
    missing = []
    for pkg in ['flask', 'flask_socketio']:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg.replace('_', '-'))

    if missing:
        print(f'  ✗ Missing packages: {", ".join(missing)}')
        print(f'  Run: pip install {" ".join(missing)}')
        sys.exit(1)

    # Optional deps check
    for pkg, name in [('yara', 'yara-python'), ('scapy', 'scapy')]:
        try:
            __import__(pkg)
            print(f'  ✓ {name} available')
        except ImportError:
            print(f'  ○ {name} not installed (optional) — pip install {name}')

    print(f'\n  Starting server on http://{args.host}:{args.port}')
    print(f'  OS: {platform.system()} {platform.release()}')
    print(f'  Open your browser → http://{"localhost" if args.host == "127.0.0.1" else args.host}:{args.port}')
    print(f'\n  ⚠  Packet capture requires root/Administrator privileges.')
    print(f'  Press Ctrl+C to stop.\n')

    from web import create_app, socketio
    app = create_app()
    socketio.run(app, host=args.host, port=args.port, debug=args.debug,
                 use_reloader=False, log_output=args.debug)


if __name__ == '__main__':
    main()
