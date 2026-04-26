"""
Network Scanner — maps active connections, open ports, and suspicious traffic patterns.
"""
import psutil
import socket
import ipaddress
from datetime import datetime
from typing import List, Dict, Any, Optional

# RFC 1918 private ranges
PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]

# Well-known C2 / suspicious ports
SUSPICIOUS_PORTS = {
    4444: 'Metasploit default',
    4445: 'Metasploit alt',
    5555: 'Android debug / reverse shell',
    6666: 'IRC / backdoor',
    6667: 'IRC (often C2)',
    7777: 'Common reverse shell',
    8888: 'Jupyter / backdoor',
    9999: 'Common backdoor',
    1337: 'Leet / hacker port',
    31337: 'Back Orifice',
    12345: 'NetBus RAT',
    54321: 'Reverse shell',
    65535: 'Possible backdoor',
}

# Ports that should never have arbitrary processes listening
CRITICAL_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5985, 5986}

# Known malicious IP ranges (sample — extend with threat intel feeds)
KNOWN_BAD_IP_PREFIXES = [
    '185.220.',  # Tor exit nodes (often abused)
    '45.142.',   # Known bulletproof hosting
    '194.165.',  # Observed C2 ranges
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ''


def _pid_to_process(pid: Optional[int]) -> Dict[str, str]:
    if not pid:
        return {'name': 'unknown', 'exe': ''}
    try:
        p = psutil.Process(pid)
        return {'name': p.name(), 'exe': p.exe() or ''}
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {'name': f'pid:{pid}', 'exe': ''}


def scan_connections() -> List[Dict[str, Any]]:
    """Enumerate all network connections with threat scoring."""
    results = []

    for conn in psutil.net_connections(kind='all'):
        flags: List[str] = []

        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ''
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ''
        rip   = conn.raddr.ip if conn.raddr else None
        rport = conn.raddr.port if conn.raddr else None
        lport = conn.laddr.port if conn.laddr else None

        # Check suspicious local port
        if lport in SUSPICIOUS_PORTS:
            flags.append(f"SUSPICIOUS_LOCAL_PORT:{lport} ({SUSPICIOUS_PORTS[lport]})")

        # Check suspicious remote port
        if rport in SUSPICIOUS_PORTS:
            flags.append(f"SUSPICIOUS_REMOTE_PORT:{rport} ({SUSPICIOUS_PORTS[rport]})")

        # Outbound to known bad IPs
        if rip:
            if any(rip.startswith(pfx) for pfx in KNOWN_BAD_IP_PREFIXES):
                flags.append(f"KNOWN_BAD_IP:{rip}")

            # Outbound non-standard ports to public IPs
            if not _is_private(rip) and rport and rport not in (80, 443, 53, 25, 587, 993, 995):
                if rport > 1024:
                    flags.append(f"UNUSUAL_OUTBOUND_PORT:{rport}")

        # Listening on all interfaces (0.0.0.0)
        if conn.laddr and conn.laddr.ip == '0.0.0.0':
            flags.append('LISTENING_ALL_INTERFACES')

        proc_info = _pid_to_process(conn.pid)

        # Resolve remote hostname (best-effort)
        remote_host = ''
        if rip and not _is_private(rip):
            remote_host = _resolve_hostname(rip)

        severity = 'OK'
        if len(flags) >= 3:
            severity = 'CRITICAL'
        elif len(flags) >= 2:
            severity = 'HIGH'
        elif len(flags) == 1:
            severity = 'MEDIUM'

        results.append({
            'pid':          conn.pid,
            'process_name': proc_info['name'],
            'process_exe':  proc_info['exe'],
            'laddr':        laddr,
            'raddr':        raddr,
            'remote_host':  remote_host,
            'status':       conn.status or '',
            'family':       str(conn.family),
            'type':         str(conn.type),
            'flags':        flags,
            'severity':     severity,
        })

    return sorted(results, key=lambda x: (x['severity'] == 'OK', x['pid'] or 0))


def scan_open_ports() -> List[Dict[str, Any]]:
    """List all listening ports with owning process."""
    results = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN or conn.status == 'LISTEN':
            proc_info = _pid_to_process(conn.pid)
            port = conn.laddr.port if conn.laddr else 0
            results.append({
                'port':         port,
                'ip':           conn.laddr.ip if conn.laddr else '',
                'pid':          conn.pid,
                'process_name': proc_info['name'],
                'process_exe':  proc_info['exe'],
                'suspicious':   port in SUSPICIOUS_PORTS,
                'note':         SUSPICIOUS_PORTS.get(port, ''),
            })
    return sorted(results, key=lambda x: x['port'])


def get_network_interfaces() -> List[Dict[str, Any]]:
    """Enumerate network interfaces and their addresses."""
    results = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for iface, addr_list in addrs.items():
        stat = stats.get(iface)
        for addr in addr_list:
            results.append({
                'interface': iface,
                'family':    str(addr.family),
                'address':   addr.address,
                'netmask':   addr.netmask or '',
                'up':        stat.isup if stat else False,
                'speed_mb':  stat.speed if stat else 0,
            })
    return results
