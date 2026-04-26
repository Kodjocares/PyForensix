"""
YARA Scanner — scans files, processes, and memory dumps against YARA rules.
Gracefully degrades if yara-python is not installed.
"""
import os
import platform
import hashlib
import struct
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# ── Built-in YARA rules (embedded — no external files needed) ─────────────────

BUILTIN_RULES = r"""
rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Detects PowerShell with base64 encoded commands"
        severity    = "HIGH"
        mitre       = "T1059.001"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "-e " nocase
        $b64  = /[A-Za-z0-9+\/]{40,}={0,2}/ ascii
    condition:
        any of ($enc*) and $b64
}

rule Meterpreter_Shellcode {
    meta:
        description = "Detects Meterpreter shellcode patterns"
        severity    = "CRITICAL"
        mitre       = "T1059"
    strings:
        $met1 = { 4d 65 74 65 72 70 72 65 74 65 72 }
        $met2 = "metsrv" nocase
        $met3 = "ReflectivLoader" nocase
        $met4 = { fc e8 8? 00 00 00 60 89 e5 31 d2 64 8b 52 30 }
    condition:
        any of them
}

rule Suspicious_PE_In_Unusual_Location {
    meta:
        description = "PE file in temp or unusual location"
        severity    = "HIGH"
        mitre       = "T1204"
    strings:
        $mz = { 4d 5a }
        $path1 = "\\Temp\\" nocase
        $path2 = "\\tmp\\" nocase
        $path3 = "AppData\\Local\\Temp" nocase
        $path4 = "/tmp/" nocase
    condition:
        $mz at 0 and any of ($path*)
}

rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz credential dumper"
        severity    = "CRITICAL"
        mitre       = "T1003.001"
    strings:
        $mimi1 = "mimikatz" nocase
        $mimi2 = "sekurlsa" nocase
        $mimi3 = "lsadump" nocase
        $mimi4 = "privilege::debug" nocase
        $mimi5 = "SspCredentialList" nocase
        $mimi6 = "wdigest.dll" nocase
        $mimi7 = { 4d 69 6d 69 4b 61 74 7a }
    condition:
        2 of them
}

rule Webshell_Generic {
    meta:
        description = "Detects common web shell patterns"
        severity    = "CRITICAL"
        mitre       = "T1505.003"
    strings:
        $php1 = "eval(base64_decode" nocase
        $php2 = "eval(gzinflate" nocase
        $php3 = "eval(str_rot13" nocase
        $php4 = "passthru($_" nocase
        $php5 = "system($_" nocase
        $php6 = "shell_exec($_" nocase
        $php7 = "preg_replace.*\/e" nocase
        $asp1 = "eval(Request" nocase
        $asp2 = "execute(request" nocase
        $jsp1 = "Runtime.exec(" nocase
        $jsp2 = "ProcessBuilder" ascii
    condition:
        2 of them
}

rule Ransomware_Extensions {
    meta:
        description = "Detects strings associated with ransomware file targeting"
        severity    = "CRITICAL"
        mitre       = "T1486"
    strings:
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypto" nocase
        $ext4 = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $ext5 = "HOW_TO_DECRYPT" nocase
        $ext6 = "README_DECRYPT" nocase
        $ext7 = "RANSOM_NOTE" nocase
        $crypt1 = "CryptEncrypt" nocase
        $crypt2 = "CryptGenKey" nocase
    condition:
        2 of ($ext*) or (1 of ($ext*) and 1 of ($crypt*))
}

rule Reverse_Shell_Indicators {
    meta:
        description = "Detects common reverse shell strings"
        severity    = "CRITICAL"
        mitre       = "T1059"
    strings:
        $rs1 = "/bin/bash -i" nocase
        $rs2 = "bash -i >& /dev/tcp/" nocase
        $rs3 = "nc -e /bin/sh" nocase
        $rs4 = "nc.exe -e cmd" nocase
        $rs5 = "python -c 'import socket" nocase
        $rs6 = "perl -e 'use Socket" nocase
        $rs7 = "0>&1 2>&1" nocase
        $rs8 = "/dev/tcp/" ascii
    condition:
        any of them
}

rule Suspicious_Script_Dropper {
    meta:
        description = "Detects script-based dropper patterns"
        severity    = "HIGH"
        mitre       = "T1105"
    strings:
        $dl1 = "Invoke-WebRequest" nocase
        $dl2 = "WebClient.DownloadFile" nocase
        $dl3 = "wget " nocase
        $dl4 = "curl " nocase
        $dl5 = "bitsadmin /transfer" nocase
        $dl6 = "certutil -urlcache" nocase
        $exe1 = "Start-Process" nocase
        $exe2 = "ShellExecute" nocase
        $exe3 = "CreateProcess" nocase
    condition:
        any of ($dl*) and any of ($exe*)
}

rule Credential_Access_Patterns {
    meta:
        description = "Detects credential harvesting patterns"
        severity    = "HIGH"
        mitre       = "T1555"
    strings:
        $cred1 = "SAMQueryInformationUser" nocase
        $cred2 = "NtlmShared.dll" nocase
        $cred3 = "/etc/shadow" nocase
        $cred4 = "id_rsa" nocase
        $cred5 = ".aws/credentials" nocase
        $cred6 = "LaZagne" nocase
        $cred7 = "CryptUnprotectData" nocase
        $cred8 = "CredentialEnumerateW" nocase
    condition:
        2 of them
}

rule Persistence_Registry {
    meta:
        description = "Detects common registry persistence techniques"
        severity    = "HIGH"
        mitre       = "T1547.001"
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $reg3 = "SYSTEM\\CurrentControlSet\\Services" nocase
        $reg4 = "RegSetValueEx" nocase
        $regw = "reg add" nocase
    condition:
        ($reg4 or $regw) and any of ($reg1, $reg2, $reg3)
}
"""


class YaraScanner:
    def __init__(self, rules_dir: Optional[str] = None):
        self.available = YARA_AVAILABLE
        self.rules = None
        self.custom_rules_dir = rules_dir
        self._compile_rules()

    def _compile_rules(self):
        if not YARA_AVAILABLE:
            return
        try:
            sources = {'builtin': BUILTIN_RULES}
            if self.custom_rules_dir and os.path.isdir(self.custom_rules_dir):
                for f in os.listdir(self.custom_rules_dir):
                    if f.endswith(('.yar', '.yara', '.rules')):
                        path = os.path.join(self.custom_rules_dir, f)
                        try:
                            with open(path) as fh:
                                sources[f] = fh.read()
                        except Exception:
                            pass
            self.rules = yara.compile(sources=sources)
        except Exception as e:
            self.rules = None
            self._compile_error = str(e)

    def scan_file(self, path: str) -> Dict[str, Any]:
        """Scan a single file against all compiled YARA rules."""
        result = {
            'path':      path,
            'matches':   [],
            'severity':  'OK',
            'scanned':   True,
            'error':     None,
            'file_hash': '',
        }

        if not YARA_AVAILABLE:
            result['error'] = 'yara-python not installed'
            result['scanned'] = False
            return result

        if not self.rules:
            result['error'] = 'No rules compiled'
            result['scanned'] = False
            return result

        try:
            result['file_hash'] = _hash_file(path)
            matches = self.rules.match(path, timeout=30)
            for m in matches:
                sev = m.meta.get('severity', 'MEDIUM')
                result['matches'].append({
                    'rule':        m.rule,
                    'description': m.meta.get('description', ''),
                    'severity':    sev,
                    'mitre':       m.meta.get('mitre', ''),
                    'strings':     [(hex(s.offset), s.identifier) for s in m.strings[:5]],
                })
            if result['matches']:
                sevs = [m['severity'] for m in result['matches']]
                result['severity'] = max(sevs, key=lambda s: ['OK','LOW','MEDIUM','HIGH','CRITICAL'].index(s) if s in ['OK','LOW','MEDIUM','HIGH','CRITICAL'] else 0)
        except yara.TimeoutError:
            result['error'] = 'Scan timeout (>30s)'
        except PermissionError:
            result['error'] = 'Permission denied'
        except Exception as e:
            result['error'] = str(e)

        return result

    def scan_directory(self, path: str, max_files: int = 500,
                       extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Recursively scan a directory. Returns only files with matches or errors."""
        results = []
        count = 0
        exts = set(extensions) if extensions else None

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and
                       d not in ('proc', 'sys', 'dev', '__pycache__', 'node_modules')]
            for fname in files:
                if count >= max_files:
                    break
                if exts and os.path.splitext(fname)[1].lower() not in exts:
                    continue
                full = os.path.join(root, fname)
                try:
                    if os.path.getsize(full) > 50 * 1024 * 1024:  # skip files > 50MB
                        continue
                except OSError:
                    continue
                r = self.scan_file(full)
                if r['matches'] or r['error']:
                    results.append(r)
                count += 1

        return sorted(results, key=lambda x: (
            ['OK','LOW','MEDIUM','HIGH','CRITICAL'].index(x['severity'])
            if x['severity'] in ['OK','LOW','MEDIUM','HIGH','CRITICAL'] else 0
        ), reverse=True)

    def scan_process_memory(self, pid: int) -> Dict[str, Any]:
        """
        Best-effort process memory scan on Linux (/proc/PID/mem).
        On Windows/macOS returns a stub.
        """
        result = {'pid': pid, 'matches': [], 'severity': 'OK', 'error': None}
        if platform.system() != 'Linux':
            result['error'] = 'Process memory scan only available on Linux'
            return result
        if not YARA_AVAILABLE or not self.rules:
            result['error'] = 'YARA not available'
            return result
        try:
            matches = self.rules.match(pid=pid, timeout=15)
            for m in matches:
                result['matches'].append({
                    'rule':        m.rule,
                    'description': m.meta.get('description', ''),
                    'severity':    m.meta.get('severity', 'MEDIUM'),
                    'mitre':       m.meta.get('mitre', ''),
                })
            if result['matches']:
                sevs = [m['severity'] for m in result['matches']]
                result['severity'] = max(sevs, key=lambda s: ['OK','LOW','MEDIUM','HIGH','CRITICAL'].index(s) if s in ['OK','LOW','MEDIUM','HIGH','CRITICAL'] else 0)
        except Exception as e:
            result['error'] = str(e)
        return result

    def get_rule_list(self) -> List[Dict[str, str]]:
        """Return metadata for all compiled rules."""
        if not YARA_AVAILABLE or not self.rules:
            return []
        rules_list = []
        for r in self.rules:
            rules_list.append({
                'name':        r.identifier,
                'description': r.meta.get('description', ''),
                'severity':    r.meta.get('severity', 'MEDIUM'),
                'mitre':       r.meta.get('mitre', ''),
                'tags':        list(r.tags),
            })
        return rules_list


def _hash_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''


# Singleton scanner instance
_scanner: Optional[YaraScanner] = None


def get_scanner(rules_dir: Optional[str] = None) -> YaraScanner:
    global _scanner
    if _scanner is None:
        _scanner = YaraScanner(rules_dir)
    return _scanner
