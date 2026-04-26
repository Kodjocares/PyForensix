"""
Process Scanner — detects suspicious processes, hollow injection, and anomalies.
"""
import psutil
import os
import platform
import hashlib
from datetime import datetime
from typing import List, Dict, Any

SUSPICIOUS_PROCESS_NAMES = {
    'mimikatz', 'procdump', 'pwdump', 'fgdump', 'wce', 'gsecdump',
    'nc.exe', 'ncat.exe', 'netcat', 'socat',
    'meterpreter', 'beacon', 'empire', 'metasploit',
    'cobaltstrike', 'psexec', 'wmic', 'regsvr32',
    'certutil', 'bitsadmin', 'mshta', 'cmstp',
    'installutil', 'regasm', 'regsvcs', 'csc.exe',
}

LOLBINS = {
    'certutil.exe', 'mshta.exe', 'wmic.exe', 'bitsadmin.exe',
    'regsvr32.exe', 'rundll32.exe', 'cmstp.exe', 'installutil.exe',
    'regasm.exe', 'regsvcs.exe', 'msiexec.exe', 'odbcconf.exe',
    'ieexec.exe', 'xwizard.exe', 'appsyncpublishingtool.exe',
}

SUSPICIOUS_PARENT_CHILD = {
    'winword.exe':   {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'},
    'excel.exe':     {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'},
    'outlook.exe':   {'cmd.exe', 'powershell.exe', 'wscript.exe'},
    'explorer.exe':  {'powershell.exe', 'cmd.exe'},
    'svchost.exe':   {'cmd.exe', 'powershell.exe', 'cscript.exe'},
    'lsass.exe':     {'cmd.exe', 'powershell.exe'},
}

SUSPICIOUS_PORTS = {4444, 4445, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321, 65535}


def _hash_exe(path: str) -> str:
    """Return SHA-256 of an executable, empty string on error."""
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read(1024 * 1024)).hexdigest()
    except Exception:
        return ''


def scan_processes() -> List[Dict[str, Any]]:
    """Full process scan with anomaly detection."""
    results = []
    pid_to_name: Dict[int, str] = {}

    # Build PID→name map first for parent-child checks
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid_to_name[proc.info['pid']] = (proc.info['name'] or '').lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    for proc in psutil.process_iter([
        'pid', 'name', 'exe', 'cmdline', 'username',
        'create_time', 'ppid', 'status', 'memory_percent', 'cpu_percent'
    ]):
        try:
            info = proc.info
            flags: List[str] = []
            name_lower = (info['name'] or '').lower()

            # 1. Known malicious name
            if any(s in name_lower for s in SUSPICIOUS_PROCESS_NAMES):
                flags.append('KNOWN_MALICIOUS_NAME')

            # 2. LOLBin usage
            if name_lower in LOLBINS:
                flags.append('LOLBIN_USAGE')

            # 3. No executable path (possible process hollowing)
            if not info['exe'] and name_lower not in ('system', 'idle', 'registry', ''):
                flags.append('NO_EXE_PATH')

            # 4. Suspicious parent→child relationship
            parent_name = pid_to_name.get(info['ppid'], '')
            if parent_name in SUSPICIOUS_PARENT_CHILD:
                if name_lower in SUSPICIOUS_PARENT_CHILD[parent_name]:
                    flags.append(f'BAD_PARENT_CHILD:{parent_name}->{name_lower}')

            # 5. Network connections on suspicious ports
            suspicious_connections = []
            try:
                for conn in proc.connections():
                    rport = conn.raddr.port if conn.raddr else None
                    lport = conn.laddr.port if conn.laddr else None
                    if rport in SUSPICIOUS_PORTS:
                        flags.append(f'SUSPICIOUS_REMOTE_PORT:{rport}')
                        suspicious_connections.append(f"{conn.laddr} -> {conn.raddr} [{conn.status}]")
                    if lport in SUSPICIOUS_PORTS:
                        flags.append(f'SUSPICIOUS_LOCAL_PORT:{lport}')
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # 6. Running from temp or user-writable dirs
            exe = info['exe'] or ''
            suspicious_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp', '/tmp/', '/var/tmp/']
            if any(p in exe.lower() for p in suspicious_paths):
                flags.append('RUNNING_FROM_TEMP')

            # 7. Hash the executable
            exe_hash = _hash_exe(exe) if exe else ''

            severity = 'OK'
            if len(flags) >= 3:
                severity = 'CRITICAL'
            elif len(flags) >= 2:
                severity = 'HIGH'
            elif len(flags) == 1:
                severity = 'MEDIUM'

            results.append({
                'pid':          info['pid'],
                'name':         info['name'] or '',
                'exe':          exe,
                'exe_hash':     exe_hash,
                'cmdline':      ' '.join(info['cmdline']) if info['cmdline'] else '',
                'username':     info['username'] or '',
                'create_time':  datetime.fromtimestamp(info['create_time']).strftime('%Y-%m-%d %H:%M:%S') if info['create_time'] else '',
                'ppid':         info['ppid'],
                'parent_name':  parent_name,
                'status':       info['status'] or '',
                'memory_pct':   round(info['memory_percent'] or 0, 2),
                'flags':        flags,
                'severity':     severity,
                'connections':  suspicious_connections,
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return sorted(results, key=lambda x: (x['severity'] == 'OK', x['pid']))
