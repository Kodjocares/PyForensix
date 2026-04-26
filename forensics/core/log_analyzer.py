"""
Log Analyzer — parses system logs for intrusion indicators.
Windows: Event Log (Security, System, Application)
Linux: /var/log/auth.log, syslog, wtmp
"""
import os
import re
import platform
import struct
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# ── Regex patterns for suspicious log entries ──────────────────────────────────

PATTERNS = {
    'SSH_BRUTE_FORCE':       re.compile(r'Failed password for .+ from ([\d.]+)', re.I),
    'SSH_ROOT_ATTEMPT':      re.compile(r'Failed password for root from ([\d.]+)', re.I),
    'SUDO_ESCALATION':       re.compile(r'sudo.*COMMAND=(.+)', re.I),
    'SU_ESCALATION':         re.compile(r'\bsu\b.*to root', re.I),
    'CRON_MODIFICATION':     re.compile(r'crontab|cron.*edit', re.I),
    'NEW_USER_CREATED':      re.compile(r'useradd|adduser|new user.*name=', re.I),
    'PASSWD_CHANGE':         re.compile(r'passwd.*changed|password.*updated', re.I),
    'SERVICE_STOPPED':       re.compile(r'stopped|deactivating.*service', re.I),
    'KERNEL_ERROR':          re.compile(r'kernel.*error|oops|panic', re.I),
    'OOM_KILL':              re.compile(r'Out of memory.*kill process|oom-kill', re.I),
    'NETWORK_SCAN':          re.compile(r'nmap|masscan|port scan', re.I),
    'SEGFAULT':              re.compile(r'segfault|segmentation fault', re.I),
    'INVALID_USER':          re.compile(r'Invalid user .+ from ([\d.]+)', re.I),
    'AUTHENTICATION_FAIL':   re.compile(r'authentication failure|auth fail', re.I),
    'ROOTKIT_INDICATOR':     re.compile(r'chkrootkit|rkhunter.*warning|suspicious file', re.I),
}

CRITICAL_PATTERNS = {
    'SSH_BRUTE_FORCE', 'SSH_ROOT_ATTEMPT', 'INVALID_USER',
    'NEW_USER_CREATED', 'SU_ESCALATION', 'ROOTKIT_INDICATOR',
}

LINUX_LOG_FILES = [
    '/var/log/auth.log',
    '/var/log/secure',
    '/var/log/syslog',
    '/var/log/messages',
    '/var/log/kern.log',
    '/var/log/faillog',
    '/var/log/apache2/access.log',
    '/var/log/nginx/access.log',
]


# ── Linux / macOS log parsing ──────────────────────────────────────────────────

def _parse_log_file(path: str, max_lines: int = 5000) -> List[Dict[str, Any]]:
    results = []
    if not os.path.isfile(path):
        return results
    try:
        with open(path, 'r', errors='replace') as f:
            lines = f.readlines()[-max_lines:]
        for lineno, line in enumerate(lines, 1):
            line = line.strip()
            for pattern_name, regex in PATTERNS.items():
                if regex.search(line):
                    results.append({
                        'source':    path,
                        'line_no':   lineno,
                        'raw':       line[:300],
                        'pattern':   pattern_name,
                        'severity':  'CRITICAL' if pattern_name in CRITICAL_PATTERNS else 'HIGH',
                        'timestamp': _extract_timestamp(line),
                    })
                    break
    except (PermissionError, UnicodeDecodeError):
        pass
    return results


def _extract_timestamp(line: str) -> str:
    """Try to extract a timestamp from a log line."""
    # Syslog format: Jan  1 12:34:56
    m = re.match(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    if m:
        return m.group(1)
    # ISO format
    m = re.search(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
    if m:
        return m.group(1)
    return ''


def scan_linux_logs(paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    logs = paths or LINUX_LOG_FILES
    results = []
    for path in logs:
        results.extend(_parse_log_file(path))
    return sorted(results, key=lambda x: x['severity'])


# ── Windows Event Log parsing ──────────────────────────────────────────────────

# Security event IDs of interest
WINDOWS_EVENT_IDS = {
    4625: ('FAILED_LOGON',          'CRITICAL'),   # Failed logon
    4624: ('SUCCESSFUL_LOGON',      'LOW'),         # Successful logon
    4634: ('LOGOFF',                'LOW'),
    4648: ('EXPLICIT_CREDENTIALS',  'HIGH'),        # Logon using explicit credentials
    4672: ('SPECIAL_PRIVILEGES',    'HIGH'),        # Special privileges assigned
    4688: ('PROCESS_CREATED',       'MEDIUM'),      # Process creation
    4698: ('SCHTASK_CREATED',       'HIGH'),        # Scheduled task created
    4699: ('SCHTASK_DELETED',       'MEDIUM'),
    4702: ('SCHTASK_MODIFIED',      'HIGH'),
    4704: ('USER_RIGHT_ASSIGNED',   'HIGH'),
    4720: ('USER_CREATED',          'CRITICAL'),    # User account created
    4722: ('USER_ENABLED',          'HIGH'),
    4725: ('USER_DISABLED',         'MEDIUM'),
    4726: ('USER_DELETED',          'HIGH'),
    4728: ('GROUP_MEMBER_ADDED',    'HIGH'),
    4732: ('LOCAL_GROUP_MEMBER',    'HIGH'),
    4756: ('UNIVERSAL_GROUP_MEMBER','HIGH'),
    4771: ('KERBEROS_PREAUTH_FAIL', 'HIGH'),
    4776: ('NTLM_AUTH_FAIL',        'HIGH'),
    1102: ('AUDIT_LOG_CLEARED',     'CRITICAL'),    # Audit log cleared
    7045: ('SERVICE_INSTALLED',     'HIGH'),        # New service installed
    7036: ('SERVICE_STATE_CHANGE',  'LOW'),
    4657: ('REGISTRY_MODIFIED',     'MEDIUM'),
}


def scan_windows_events(hours: int = 24, max_events: int = 500) -> List[Dict[str, Any]]:
    """
    Read Windows Security/System event logs via win32evtlog.
    Falls back gracefully on non-Windows systems.
    """
    if platform.system() != 'Windows':
        return [{'source': 'N/A', 'message': 'Windows Event Log only available on Windows.', 'severity': 'INFO'}]

    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        import pywintypes
    except ImportError:
        return [{'source': 'N/A', 'message': 'pywin32 not installed. Run: pip install pywin32', 'severity': 'INFO'}]

    cutoff = datetime.now() - timedelta(hours=hours)
    results = []

    for log_type in ('Security', 'System', 'Application'):
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            count = 0
            while events and count < max_events:
                for ev in events:
                    if count >= max_events:
                        break
                    eid = ev.EventID & 0xFFFF
                    if eid not in WINDOWS_EVENT_IDS:
                        continue
                    ev_name, severity = WINDOWS_EVENT_IDS[eid]
                    try:
                        msg = win32evtlogutil.SafeFormatMessage(ev, log_type)
                    except Exception:
                        msg = str(ev.StringInserts or '')
                    results.append({
                        'source':    log_type,
                        'event_id':  eid,
                        'type':      ev_name,
                        'severity':  severity,
                        'timestamp': ev.TimeGenerated.Format(),
                        'message':   (msg or '')[:400],
                        'computer':  ev.ComputerName,
                    })
                    count += 1
                events = win32evtlog.ReadEventLog(hand, flags, 0)
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            results.append({'source': log_type, 'message': str(e), 'severity': 'INFO'})

    return sorted(results, key=lambda x: x.get('severity', 'LOW'))


# ── Brute-force summary ────────────────────────────────────────────────────────

def summarize_brute_force(log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Aggregate failed SSH/auth attempts by IP to surface brute-force sources.
    """
    from collections import Counter
    ip_counts: Counter = Counter()
    for entry in log_entries:
        if entry.get('pattern') in ('SSH_BRUTE_FORCE', 'INVALID_USER', 'SSH_ROOT_ATTEMPT'):
            m = re.search(r'from ([\d.]+)', entry.get('raw', ''))
            if m:
                ip_counts[m.group(1)] += 1

    return [
        {'ip': ip, 'attempts': cnt, 'severity': 'CRITICAL' if cnt >= 20 else 'HIGH'}
        for ip, cnt in ip_counts.most_common(20)
        if cnt >= 3
    ]
