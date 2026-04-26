"""
File Scanner — baseline hashing, SUID/SGID checks, recently modified files, and hidden files.
"""
import os
import stat
import hashlib
import platform
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

BASELINE_FILE = 'baseline.json'

# High-value system paths to monitor
MONITOR_PATHS = {
    'Windows': [
        r'C:\Windows\System32',
        r'C:\Windows\SysWOW64',
        r'C:\Windows\system.ini',
        r'C:\Windows\win.ini',
    ],
    'Linux': [
        '/bin', '/sbin', '/usr/bin', '/usr/sbin',
        '/etc/passwd', '/etc/shadow', '/etc/sudoers',
        '/etc/ssh/sshd_config', '/etc/crontab',
    ],
    'Darwin': [
        '/bin', '/sbin', '/usr/bin', '/usr/sbin',
        '/etc/passwd', '/etc/sudoers',
    ],
}

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.jse',
    '.wsf', '.wsh', '.hta', '.scr', '.pif', '.com', '.cmd',
    '.msi', '.reg', '.inf',
}


def _hash_file(path: str, algo: str = 'sha256') -> str:
    """Return hex digest of a file. Returns empty string on failure."""
    h = hashlib.new(algo)
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return ''


def _get_file_meta(path: str) -> Dict[str, Any]:
    try:
        st = os.stat(path)
        return {
            'size':    st.st_size,
            'mtime':   datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'ctime':   datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'mode':    oct(st.st_mode),
            'uid':     getattr(st, 'st_uid', None),
            'gid':     getattr(st, 'st_gid', None),
        }
    except Exception:
        return {}


def scan_recently_modified(hours: int = 24, paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Find files modified in the last `hours` hours under the given paths.
    Defaults to OS-appropriate monitor paths.
    """
    system = platform.system()
    if paths is None:
        paths = MONITOR_PATHS.get(system, [])

    cutoff = datetime.now() - timedelta(hours=hours)
    results = []

    for base in paths:
        if os.path.isfile(base):
            _check_file(base, cutoff, results)
        elif os.path.isdir(base):
            for root, dirs, files in os.walk(base):
                # Skip hidden dirs
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for fname in files:
                    full = os.path.join(root, fname)
                    _check_file(full, cutoff, results)

    return sorted(results, key=lambda x: x['mtime'], reverse=True)


def _check_file(path: str, cutoff: datetime, results: list):
    try:
        mtime = os.path.getmtime(path)
        if datetime.fromtimestamp(mtime) >= cutoff:
            ext = os.path.splitext(path)[1].lower()
            flags = []
            if ext in SUSPICIOUS_EXTENSIONS:
                flags.append('SUSPICIOUS_EXTENSION')
            if os.path.basename(path).startswith('.'):
                flags.append('HIDDEN_FILE')
            results.append({
                'path':    path,
                'mtime':   datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'size':    os.path.getsize(path),
                'ext':     ext,
                'flags':   flags,
                'hash':    _hash_file(path),
            })
    except (PermissionError, FileNotFoundError, OSError):
        pass


def scan_suid_sgid(base: str = '/') -> List[Dict[str, Any]]:
    """
    Linux/macOS only: find SUID and SGID files which can be used for privilege escalation.
    """
    if platform.system() == 'Windows':
        return []
    results = []
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in ('proc', 'sys', 'dev')]
        for fname in files:
            full = os.path.join(root, fname)
            try:
                st = os.stat(full)
                mode = st.st_mode
                flags = []
                if mode & stat.S_ISUID:
                    flags.append('SUID')
                if mode & stat.S_ISGID:
                    flags.append('SGID')
                if flags:
                    results.append({
                        'path':    full,
                        'mode':    oct(mode),
                        'owner':   st.st_uid,
                        'group':   st.st_gid,
                        'size':    st.st_size,
                        'flags':   flags,
                    })
            except (PermissionError, FileNotFoundError):
                pass
    return results


def generate_baseline(paths: Optional[List[str]] = None, output_file: str = BASELINE_FILE) -> Dict[str, str]:
    """
    Hash all files in the given paths and save as a baseline JSON.
    Returns the {path: hash} map.
    """
    system = platform.system()
    if paths is None:
        paths = MONITOR_PATHS.get(system, [])

    baseline: Dict[str, str] = {}
    for base in paths:
        if os.path.isfile(base):
            h = _hash_file(base)
            if h:
                baseline[base] = h
        elif os.path.isdir(base):
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for fname in files:
                    full = os.path.join(root, fname)
                    h = _hash_file(full)
                    if h:
                        baseline[full] = h

    with open(output_file, 'w') as f:
        json.dump({'generated': datetime.now().isoformat(), 'files': baseline}, f, indent=2)

    return baseline


def verify_baseline(baseline_file: str = BASELINE_FILE) -> List[Dict[str, Any]]:
    """
    Compare current file hashes against the saved baseline.
    Returns a list of changed/missing/new files.
    """
    if not os.path.exists(baseline_file):
        return [{'status': 'NO_BASELINE', 'message': f'Baseline file {baseline_file} not found.'}]

    with open(baseline_file) as f:
        data = json.load(f)

    saved = data.get('files', {})
    results = []

    for path, expected_hash in saved.items():
        if not os.path.exists(path):
            results.append({'path': path, 'status': 'DELETED', 'expected': expected_hash, 'actual': ''})
        else:
            actual = _hash_file(path)
            if actual != expected_hash:
                results.append({'path': path, 'status': 'MODIFIED', 'expected': expected_hash, 'actual': actual})

    # New files not in baseline
    system = platform.system()
    current = {}
    for base in MONITOR_PATHS.get(system, []):
        if os.path.isdir(base):
            for root, _, files in os.walk(base):
                for fname in files:
                    full = os.path.join(root, fname)
                    if full not in saved:
                        results.append({'path': full, 'status': 'NEW', 'expected': '', 'actual': _hash_file(full)})

    return results
