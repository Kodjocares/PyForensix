#!/usr/bin/env python3
"""
PyForensix — System Forensics & Intrusion Detection Toolkit
============================================================
Usage:
  python main.py            # Launch GUI
  python main.py --cli      # Run CLI scan (no GUI required)
  python main.py --help
"""

import argparse
import sys
import platform
import os
import json
from datetime import datetime


def print_banner():
    banner = r"""
 ██████╗ ██╗   ██╗███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██╗  ██╗
 ██╔══██╗╚██╗ ██╔╝██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║╚██╗██╔╝
 ██████╔╝ ╚████╔╝ █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║ ╚███╔╝ 
 ██╔═══╝   ╚██╔╝  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║ ██╔██╗ 
 ██║        ██║   ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██╔╝ ██╗
 ╚═╝        ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝
    System Forensics & Intrusion Detection Toolkit
"""
    print(banner)
    print(f'  Version  : 1.0.0')
    print(f'  Python   : {sys.version.split()[0]}')
    print(f'  OS       : {platform.system()} {platform.release()}')
    print(f'  Time     : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print()


def run_cli_scan(args):
    """Execute a full scan from the command line with rich terminal output."""
    from forensics.core.system_info       import get_system_info, get_startup_items
    from forensics.core.process_scanner   import scan_processes
    from forensics.core.network_scanner   import scan_connections, scan_open_ports
    from forensics.core.file_scanner      import scan_recently_modified
    from forensics.core.log_analyzer      import scan_linux_logs, scan_windows_events, summarize_brute_force
    from forensics.core.intrusion_detector import build_report
    from forensics.utils.reporter         import generate_html_report, generate_json_report, generate_csv_report

    # ANSI colors
    RED    = '\033[91m'
    ORANGE = '\033[93m'
    GREEN  = '\033[92m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    RESET  = '\033[0m'
    BOLD   = '\033[1m'

    sev_colors = {
        'CRITICAL': RED + BOLD,
        'HIGH':     ORANGE,
        'MEDIUM':   ORANGE,
        'LOW':      GREEN,
        'CLEAN':    GREEN,
        'OK':       '',
    }

    def hdr(title):
        print(f'\n{CYAN}{"─"*60}{RESET}')
        print(f'{BOLD}{CYAN}  {title}{RESET}')
        print(f'{CYAN}{"─"*60}{RESET}')

    def progress(msg):
        print(f'  {BLUE}→{RESET} {msg}...')

    progress('Collecting system info')
    sysinfo = get_system_info()
    startup = get_startup_items()

    progress('Scanning processes')
    processes = scan_processes()

    progress('Scanning network connections')
    conns = scan_connections()
    ports = scan_open_ports()

    hours = args.hours if hasattr(args, 'hours') else 24
    progress(f'Scanning recently modified files (last {hours}h)')
    files = scan_recently_modified(hours=hours)

    progress('Analyzing system logs')
    if platform.system() == 'Windows':
        logs = scan_windows_events()
    else:
        logs = scan_linux_logs()
    brute = summarize_brute_force(logs)

    progress('Building intrusion report')
    report = build_report(
        processes=processes,
        connections=conns,
        open_ports=ports,
        recent_files=files,
        log_entries=logs,
        brute_force=brute,
        startup=startup,
    )
    rd = report.to_dict()

    # ── Print results ──────────────────────────────────────────────────────

    hdr('SYSTEM INFO')
    skip_keys = {'disks', 'scan_time'}
    for k, v in sysinfo.items():
        if k not in skip_keys and not isinstance(v, list):
            print(f'  {k.replace("_"," ").upper():<20} {v}')

    hdr('RISK SUMMARY')
    risk  = rd['risk_level']
    score = rd['score']
    color = sev_colors.get(risk, '')
    print(f'  {BOLD}Risk Level : {color}{risk}{RESET}')
    print(f'  Threat Score: {score}')
    summary = rd.get('summary', {})
    for sev, cnt in [('CRITICAL', summary.get('CRITICAL',0)),
                     ('HIGH',     summary.get('HIGH',0)),
                     ('MEDIUM',   summary.get('MEDIUM',0)),
                     ('LOW',      summary.get('LOW',0))]:
        bar = '█' * min(cnt, 40)
        col = sev_colors.get(sev, '')
        print(f'  {sev:<10} {col}{bar} {cnt}{RESET}')

    # Alerts
    alerts = [a for a in rd.get('alerts', []) if a.get('severity') in ('CRITICAL', 'HIGH', 'MEDIUM')]
    if alerts:
        hdr(f'ALERTS ({len(alerts)})')
        for a in sorted(alerts, key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW'].index(x.get('severity','LOW'))):
            sev   = a.get('severity', '')
            col   = sev_colors.get(sev, '')
            techs = ', '.join(t['id'] for t in a.get('techniques', []))
            print(f'  [{col}{sev:8}{RESET}] {a["category"]:12} {a["title"][:70]}')
            if techs:
                print(f'  {" ":11} MITRE: {BLUE}{techs}{RESET}')
            for rem in a.get('remediation', []):
                if rem:
                    print(f'  {" ":11} FIX:   {rem[:80]}')
    else:
        hdr('ALERTS')
        print(f'  {GREEN}No high-severity findings detected.{RESET}')

    # Suspicious processes
    susp_procs = [p for p in processes if p['flags']]
    if susp_procs:
        hdr(f'SUSPICIOUS PROCESSES ({len(susp_procs)})')
        for p in susp_procs[:20]:
            col = sev_colors.get(p['severity'], '')
            print(f'  {col}[{p["severity"]:8}]{RESET} PID {p["pid"]:6} {p["name"]:<22} {", ".join(p["flags"][:3])}')

    # Brute force
    if brute:
        hdr(f'BRUTE FORCE SOURCES ({len(brute)})')
        for b in brute[:10]:
            print(f'  {RED}{b["ip"]:<18}{RESET} {b["attempts"]:>5} attempts')

    # ── Export ─────────────────────────────────────────────────────────────

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    exported = []

    if args.html or args.all:
        path = f'pyforensix_report_{ts}.html'
        generate_html_report(rd, sysinfo, path)
        exported.append(f'HTML → {path}')

    if args.json or args.all:
        path = f'pyforensix_report_{ts}.json'
        generate_json_report(rd, sysinfo, path)
        exported.append(f'JSON → {path}')

    if args.csv or args.all:
        path = f'pyforensix_alerts_{ts}.csv'
        generate_csv_report(rd.get('alerts', []), path)
        exported.append(f'CSV  → {path}')

    if exported:
        hdr('EXPORTED')
        for e in exported:
            print(f'  {GREEN}✓{RESET} {e}')

    print()
    return 0 if risk in ('CLEAN', 'LOW') else 1


def main():
    parser = argparse.ArgumentParser(
        description='PyForensix — System Forensics & Intrusion Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Examples:
  python main.py                  Launch GUI
  python main.py --cli            CLI scan, print results
  python main.py --cli --html     CLI scan + export HTML report
  python main.py --cli --all      CLI scan + export all formats
  python main.py --cli --hours 6  Scan files modified in last 6h
        ''')
    parser.add_argument('--cli',   action='store_true', help='Run in CLI mode (no GUI)')
    parser.add_argument('--html',  action='store_true', help='Export HTML report')
    parser.add_argument('--json',  action='store_true', help='Export JSON report')
    parser.add_argument('--csv',   action='store_true', help='Export CSV alerts')
    parser.add_argument('--all',   action='store_true', help='Export all formats')
    parser.add_argument('--hours', type=int, default=24,
                        help='Hours window for recent-file scan (default: 24)')
    args = parser.parse_args()

    print_banner()

    if args.cli:
        sys.exit(run_cli_scan(args))
    else:
        try:
            from forensics.gui.dashboard import run_gui
            run_gui()
        except ImportError as e:
            print(f'GUI unavailable: {e}')
            print('Falling back to CLI mode. Use --cli explicitly next time.')
            sys.exit(run_cli_scan(args))


if __name__ == '__main__':
    main()
