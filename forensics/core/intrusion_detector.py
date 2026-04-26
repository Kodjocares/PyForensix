"""
Intrusion Detector — aggregates findings from all scanners into a unified threat report
with severity scoring, MITRE ATT&CK tagging, and recommended actions.
"""
from datetime import datetime
from typing import List, Dict, Any, Tuple

# MITRE ATT&CK technique tags
MITRE_TAGS = {
    'KNOWN_MALICIOUS_NAME':      ('T1059',  'Command and Scripting Interpreter'),
    'LOLBIN_USAGE':              ('T1218',  'System Binary Proxy Execution'),
    'NO_EXE_PATH':               ('T1055',  'Process Injection'),
    'BAD_PARENT_CHILD':          ('T1059',  'Command and Scripting Interpreter'),
    'RUNNING_FROM_TEMP':         ('T1204',  'User Execution'),
    'SUSPICIOUS_REMOTE_PORT':    ('T1571',  'Non-Standard Port'),
    'SUSPICIOUS_LOCAL_PORT':     ('T1571',  'Non-Standard Port'),
    'UNUSUAL_OUTBOUND_PORT':     ('T1048',  'Exfiltration Over Alternative Protocol'),
    'KNOWN_BAD_IP':              ('T1071',  'Application Layer Protocol'),
    'LISTENING_ALL_INTERFACES':  ('T1133',  'External Remote Services'),
    'SUSPICIOUS_EXTENSION':      ('T1036',  'Masquerading'),
    'HIDDEN_FILE':               ('T1564',  'Hide Artifacts'),
    'MODIFIED':                  ('T1565',  'Data Manipulation'),
    'NEW_USER_CREATED':          ('T1136',  'Create Account'),
    'SU_ESCALATION':             ('T1548',  'Abuse Elevation Control Mechanism'),
    'SSH_BRUTE_FORCE':           ('T1110',  'Brute Force'),
    'AUDIT_LOG_CLEARED':         ('T1070',  'Indicator Removal on Host'),
    'SCHTASK_CREATED':           ('T1053',  'Scheduled Task/Job'),
    'SERVICE_INSTALLED':         ('T1543',  'Create or Modify System Process'),
    'REGISTRY_MODIFIED':         ('T1112',  'Modify Registry'),
    'CRON_MODIFICATION':         ('T1053',  'Scheduled Task/Job'),
    'ROOTKIT_INDICATOR':         ('T1014',  'Rootkit'),
    'STARTUP_ITEM':              ('T1547',  'Boot or Logon Autostart Execution'),
}

REMEDIATION = {
    'T1059': 'Review the process and its parent. Block execution via AppLocker or Software Restriction Policies.',
    'T1218': 'Investigate LOLBin usage. Consider blocking unused interpreters via application control.',
    'T1055': 'Investigate for process hollowing or DLL injection. Check parent process legitimately launched the child.',
    'T1571': 'Block non-standard outbound ports at the firewall. Investigate the process listening or connecting.',
    'T1048': 'Block non-standard outbound ports. Enable DLP. Review data leaving the network.',
    'T1071': 'Block the destination IP. Investigate process establishing the connection.',
    'T1133': 'Verify service legitimacy. Disable if unauthorized.',
    'T1036': 'Verify file authenticity. Check digital signature and hash against known-good.',
    'T1564': 'Investigate hidden files. Check for webshells, persistence scripts, or malware stashes.',
    'T1565': 'Restore from backup. Investigate the process that modified the file.',
    'T1136': 'Immediately lock unauthorized accounts. Investigate the source of account creation.',
    'T1548': 'Investigate privilege escalation path. Review sudoers and setuid binaries.',
    'T1110': 'Block source IP. Enforce account lockout policy. Enable MFA on exposed services.',
    'T1070': 'Audit log clearing is a critical indicator of attacker cleanup. Assume full compromise — invoke IR.',
    'T1053': 'Review scheduled tasks/cron jobs. Delete unauthorized entries.',
    'T1543': 'Review installed service. Stop and disable if unauthorized. Investigate binary.',
    'T1112': 'Review registry changes. Restore from known-good state if unauthorized.',
    'T1014': 'Rootkit indicators require offline analysis. Boot from trusted media and run full AV/rootkit scan.',
    'T1547': 'Review startup entries. Remove unauthorized persistence.',
}

SEVERITY_SCORE = {'CRITICAL': 40, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5, 'OK': 0, 'INFO': 0}


class IntrusionReport:
    def __init__(self):
        self.alerts:       List[Dict[str, Any]] = []
        self.score:        int = 0
        self.risk_level:   str = 'CLEAN'
        self.scan_time:    str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.summary:      Dict[str, int] = {
            'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'TOTAL': 0
        }

    def add_alert(self, category: str, title: str, detail: str,
                  severity: str, flags: List[str], source_data: Dict):
        techniques = []
        remediations = set()
        for flag in flags:
            # Match flag prefix against MITRE tags
            for key, (tid, tname) in MITRE_TAGS.items():
                if flag.startswith(key):
                    techniques.append({'id': tid, 'name': tname})
                    remediations.add(REMEDIATION.get(tid, ''))
                    break

        self.alerts.append({
            'category':    category,
            'title':       title,
            'detail':      detail,
            'severity':    severity,
            'flags':       flags,
            'techniques':  techniques,
            'remediation': list(remediations),
            'source':      source_data,
        })
        self.score += SEVERITY_SCORE.get(severity, 0)
        if severity in self.summary:
            self.summary[severity] += 1
        self.summary['TOTAL'] += 1

    def finalize(self):
        if self.score >= 100:
            self.risk_level = 'CRITICAL'
        elif self.score >= 50:
            self.risk_level = 'HIGH'
        elif self.score >= 20:
            self.risk_level = 'MEDIUM'
        elif self.score > 0:
            self.risk_level = 'LOW'
        else:
            self.risk_level = 'CLEAN'

    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_time':  self.scan_time,
            'risk_level': self.risk_level,
            'score':      self.score,
            'summary':    self.summary,
            'alerts':     self.alerts,
        }


def build_report(
    processes:    List[Dict] = None,
    connections:  List[Dict] = None,
    open_ports:   List[Dict] = None,
    recent_files: List[Dict] = None,
    log_entries:  List[Dict] = None,
    brute_force:  List[Dict] = None,
    startup:      List[Dict] = None,
    baseline_diff: List[Dict] = None,
) -> IntrusionReport:
    """Aggregate all scan results into a unified IntrusionReport."""

    report = IntrusionReport()

    # ── Processes ──────────────────────────────────────────────────────────────
    for p in (processes or []):
        if p['flags']:
            report.add_alert(
                category='PROCESS',
                title=f"Suspicious process: {p['name']} (PID {p['pid']})",
                detail=f"Exe: {p['exe'] or 'N/A'} | User: {p['username']} | CMD: {p['cmdline'][:120]}",
                severity=p['severity'],
                flags=p['flags'],
                source_data=p,
            )

    # ── Network ────────────────────────────────────────────────────────────────
    for c in (connections or []):
        if c['flags']:
            report.add_alert(
                category='NETWORK',
                title=f"Suspicious connection: {c['process_name']} → {c['raddr'] or c['laddr']}",
                detail=f"Process: {c['process_name']} | Status: {c['status']} | Host: {c['remote_host']}",
                severity=c['severity'],
                flags=c['flags'],
                source_data=c,
            )

    for p in (open_ports or []):
        if p.get('suspicious'):
            report.add_alert(
                category='NETWORK',
                title=f"Known-bad port open: {p['port']} ({p['note']})",
                detail=f"Process: {p['process_name']} | PID: {p['pid']}",
                severity='HIGH',
                flags=[f"SUSPICIOUS_LOCAL_PORT:{p['port']}"],
                source_data=p,
            )

    # ── File system ────────────────────────────────────────────────────────────
    for f in (recent_files or []):
        if f.get('flags'):
            report.add_alert(
                category='FILE',
                title=f"Suspicious recent file: {f['path']}",
                detail=f"Modified: {f['mtime']} | Size: {f['size']} bytes | Hash: {f['hash'][:16]}…",
                severity='MEDIUM',
                flags=f['flags'],
                source_data=f,
            )

    for diff in (baseline_diff or []):
        if diff.get('status') in ('MODIFIED', 'DELETED', 'NEW'):
            sev = 'CRITICAL' if diff['status'] == 'MODIFIED' else 'HIGH'
            report.add_alert(
                category='INTEGRITY',
                title=f"File integrity violation [{diff['status']}]: {diff['path']}",
                detail=f"Expected: {diff.get('expected','')[:32]}… | Actual: {diff.get('actual','')[:32]}…",
                severity=sev,
                flags=['MODIFIED' if diff['status'] == 'MODIFIED' else 'HIDDEN_FILE'],
                source_data=diff,
            )

    # ── Logs ───────────────────────────────────────────────────────────────────
    for entry in (log_entries or []):
        if entry.get('pattern'):
            report.add_alert(
                category='LOG',
                title=f"Log indicator [{entry['pattern']}] in {entry.get('source','')}",
                detail=entry.get('raw', entry.get('message', ''))[:300],
                severity=entry.get('severity', 'MEDIUM'),
                flags=[entry['pattern']],
                source_data=entry,
            )

    # ── Brute force ────────────────────────────────────────────────────────────
    for bf in (brute_force or []):
        report.add_alert(
            category='BRUTE_FORCE',
            title=f"Brute force detected from {bf['ip']} ({bf['attempts']} attempts)",
            detail=f"Source IP: {bf['ip']} | Failed auth attempts: {bf['attempts']}",
            severity=bf.get('severity', 'CRITICAL'),
            flags=['SSH_BRUTE_FORCE'],
            source_data=bf,
        )

    # ── Startup persistence ────────────────────────────────────────────────────
    for item in (startup or []):
        if item.get('suspicious'):
            report.add_alert(
                category='PERSISTENCE',
                title=f"Suspicious startup entry: {item['name']}",
                detail=f"Source: {item['source']} | Command: {item['command'][:200]}",
                severity='HIGH',
                flags=['STARTUP_ITEM'],
                source_data=item,
            )

    report.finalize()
    return report
