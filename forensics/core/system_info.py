"""
System Info — collects OS, hardware, user, and startup metadata.
"""
import platform
import socket
import os
import getpass
import psutil
import subprocess
from datetime import datetime
from typing import Dict, Any, List


def get_system_info() -> Dict[str, Any]:
    """Collect comprehensive system metadata."""
    boot_time = psutil.boot_time()
    mem = psutil.virtual_memory()
    disk_parts = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disk_parts.append({
                'device':     part.device,
                'mountpoint': part.mountpoint,
                'fstype':     part.fstype,
                'total_gb':   round(usage.total / 1e9, 2),
                'used_gb':    round(usage.used / 1e9, 2),
                'free_gb':    round(usage.free / 1e9, 2),
                'pct_used':   usage.percent,
            })
        except PermissionError:
            pass

    return {
        'hostname':      socket.gethostname(),
        'fqdn':          socket.getfqdn(),
        'os':            platform.system(),
        'os_release':    platform.release(),
        'os_version':    platform.version(),
        'architecture':  platform.machine(),
        'processor':     platform.processor(),
        'python_ver':    platform.python_version(),
        'cpu_count':     psutil.cpu_count(logical=True),
        'cpu_physical':  psutil.cpu_count(logical=False),
        'cpu_pct':       psutil.cpu_percent(interval=1),
        'ram_total_gb':  round(mem.total / 1e9, 2),
        'ram_used_gb':   round(mem.used / 1e9, 2),
        'ram_pct':       mem.percent,
        'boot_time':     datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S'),
        'uptime_hrs':    round((datetime.now().timestamp() - boot_time) / 3600, 1),
        'current_user':  getpass.getuser(),
        'scan_time':     datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'disks':         disk_parts,
    }


def get_logged_in_users() -> List[Dict[str, Any]]:
    """Get currently logged-in users."""
    users = []
    for u in psutil.users():
        users.append({
            'name':       u.name,
            'terminal':   u.terminal or 'console',
            'host':       u.host or 'local',
            'started':    datetime.fromtimestamp(u.started).strftime('%Y-%m-%d %H:%M:%S'),
            'pid':        u.pid,
        })
    return users


def get_startup_items() -> List[Dict[str, Any]]:
    """
    Retrieve startup items.
    Windows: checks common Run registry keys + startup folders.
    Linux/macOS: checks /etc/init.d, systemd units, cron.
    """
    items = []
    system = platform.system()

    if system == 'Windows':
        import winreg
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_CURRENT_USER,  r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_CURRENT_USER,  r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
        ]
        for hive, subkey in run_keys:
            try:
                key = winreg.OpenKey(hive, subkey)
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        items.append({
                            'source':    f'Registry: {subkey}',
                            'name':      name,
                            'command':   data,
                            'suspicious': _is_suspicious_startup(data),
                        })
                        i += 1
                    except OSError:
                        break
            except (FileNotFoundError, PermissionError):
                pass

        # Startup folders
        for folder in [
            os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.expandvars(r'%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup'),
        ]:
            if os.path.isdir(folder):
                for f in os.listdir(folder):
                    fpath = os.path.join(folder, f)
                    items.append({
                        'source':     'Startup Folder',
                        'name':       f,
                        'command':    fpath,
                        'suspicious': _is_suspicious_startup(fpath),
                    })

    elif system == 'Linux':
        # Systemd enabled units
        try:
            out = subprocess.check_output(
                ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--plain'],
                stderr=subprocess.DEVNULL, text=True
            )
            for line in out.splitlines():
                parts = line.split()
                if parts and parts[0].endswith('.service'):
                    items.append({
                        'source':     'systemd',
                        'name':       parts[0],
                        'command':    ' '.join(parts[1:]),
                        'suspicious': False,
                    })
        except Exception:
            pass

        # Crontab
        cron_files = []
        for p in ['/etc/crontab', '/var/spool/cron']:
            if os.path.isfile(p):
                cron_files.append(p)
            elif os.path.isdir(p):
                for f in os.listdir(p):
                    cron_files.append(os.path.join(p, f))
        for cf in cron_files:
            try:
                with open(cf) as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            items.append({
                                'source':     f'cron:{cf}',
                                'name':       cf,
                                'command':    line,
                                'suspicious': _is_suspicious_startup(line),
                            })
            except Exception:
                pass

    elif system == 'Darwin':
        launchd_dirs = [
            '/Library/LaunchDaemons', '/Library/LaunchAgents',
            os.path.expanduser('~/Library/LaunchAgents'),
        ]
        for d in launchd_dirs:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    items.append({
                        'source':     f'launchd:{d}',
                        'name':       f,
                        'command':    os.path.join(d, f),
                        'suspicious': False,
                    })

    return items


def _is_suspicious_startup(cmd: str) -> bool:
    cmd = cmd.lower()
    suspicious_indicators = [
        'powershell', 'mshta', 'wscript', 'cscript', 'regsvr32',
        'rundll32', 'certutil', 'bitsadmin', 'temp\\', '/tmp/',
        'appdata\\local\\temp', 'base64', '-enc', '-encodedcommand',
        '.vbs', '.js', '.ps1',
    ]
    return any(ind in cmd for ind in suspicious_indicators)
