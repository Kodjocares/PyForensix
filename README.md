# ⚡ PyForensix

**System Forensics & Intrusion Detection Toolkit**

A cross-platform Python toolkit for digital forensics and intrusion detection. Runs as a full **GUI dashboard** (Tkinter) or as a **CLI tool** for headless/server environments. Produces HTML, JSON, and CSV reports with MITRE ATT&CK tagging and remediation guidance.

---

## Features

| Domain | What it detects |
|---|---|
| **Process Analysis** | Suspicious names, LOLBins, process hollowing (no exe path), bad parent→child chains, reverse shell ports |
| **Network Forensics** | Active connections, known-bad ports, unusual outbound ports, public IP destinations, listening on all interfaces |
| **File Integrity** | Recently modified files, hidden files, SUID/SGID binaries (Linux), baseline hash comparison |
| **Log Analysis** | SSH brute force, privilege escalation, new user creation, audit log cleared, scheduled task creation |
| **Brute Force** | Aggregates failed auth attempts by IP, surfaces top attackers |
| **Persistence** | Startup items (Registry Run keys, Startup folder, systemd, cron, launchd), suspicious command indicators |
| **Reporting** | HTML report with MITRE ATT&CK map, JSON (machine-readable), CSV (spreadsheet) |

---

## Quick Start

### 1. Install dependencies

```bash
git clone https://github.com/yourname/pyforensix.git
cd pyforensix
pip install -r requirements.txt

# Windows users (for Event Log access):
pip install pywin32
```

### 2. Launch the GUI

```bash
python main.py
```

### 3. CLI mode (headless / server)

```bash
# Run full scan, print results to terminal
python main.py --cli

# Export reports
python main.py --cli --html            # HTML report
python main.py --cli --json            # JSON report
python main.py --cli --all             # All formats

# Custom file scan window
python main.py --cli --hours 6         # Files modified in last 6 hours
```

### 4. Install as a package

```bash
pip install -e .
pyforensix --cli --all
```

---

## GUI Overview

```
┌─────────────────────────────────────────────────────────────────┐
│ ⚡ PYFORENSIX          Forensic Analysis & Intrusion Detection   │
├─────────────────────────────────────────────────────────────────┤
│ ▸ Threat Level: HIGH            Threat Score: 80               │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────┤
│ Overview │ Processes│ Network  │  Files   │   Logs   │ Alerts  │
├──────────┴──────────┴──────────┴──────────┴──────────┴─────────┤
│                                                                  │
│  [ CRITICAL: 2 ]  [ HIGH: 5 ]  [ MEDIUM: 8 ]  [ LOW: 3 ]      │
│                                                                  │
│  System Info                  Top Alerts                        │
│  ─────────────────            ─────────────────────────────     │
│  Hostname: ...                [CRITICAL] PROCESS  nc.exe...     │
│  OS: Linux 6.1.0              [HIGH]     NETWORK  port 4444     │
│  RAM: 8.0 GB                  [MEDIUM]   FILE     /tmp/evil.sh  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
pyforensix/
├── main.py                          # Entry point (GUI + CLI)
├── requirements.txt
├── setup.py
├── README.md
├── .gitignore
└── forensics/
    ├── core/
    │   ├── system_info.py           # OS, hardware, users, startup items
    │   ├── process_scanner.py       # Process analysis + anomaly detection
    │   ├── network_scanner.py       # Connections, ports, interface info
    │   ├── file_scanner.py          # File integrity, SUID, recent changes
    │   ├── log_analyzer.py          # Log parsing (Linux syslog + Windows EVTX)
    │   └── intrusion_detector.py    # Aggregates findings → IntrusionReport
    ├── utils/
    │   └── reporter.py              # HTML / JSON / CSV report generation
    └── gui/
        └── dashboard.py             # Tkinter GUI dashboard
```

---

## MITRE ATT&CK Coverage

PyForensix maps detected indicators to MITRE ATT&CK techniques automatically:

| Indicator | Technique ID | Name |
|---|---|---|
| LOLBin usage | T1218 | System Binary Proxy Execution |
| Process hollowing | T1055 | Process Injection |
| Non-standard port | T1571 | Non-Standard Port |
| New account created | T1136 | Create Account |
| Audit log cleared | T1070 | Indicator Removal on Host |
| Scheduled task | T1053 | Scheduled Task/Job |
| Brute force | T1110 | Brute Force |
| Startup persistence | T1547 | Boot or Logon Autostart Execution |
| Rootkit indicator | T1014 | Rootkit |
| Registry modification | T1112 | Modify Registry |

---

## File Integrity Baseline

```bash
# Generate a baseline hash of monitored paths
python - <<'EOF'
from forensics.core.file_scanner import generate_baseline
generate_baseline()
print("Baseline saved to baseline.json")
EOF

# Later: verify against baseline
python - <<'EOF'
from forensics.core.file_scanner import verify_baseline
diffs = verify_baseline()
for d in diffs:
    print(d['status'], d['path'])
EOF
```

---

## Platform Support

| OS | Processes | Network | Files | Logs | Registry | SUID |
|---|---|---|---|---|---|---|
| Linux | ✅ | ✅ | ✅ | ✅ | N/A | ✅ |
| macOS | ✅ | ✅ | ✅ | ✅ | N/A | ✅ |
| Windows | ✅ | ✅ | ✅ | ✅ (pywin32) | ✅ | N/A |

---

## License

MIT License — free to use, modify, and distribute.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit: `git commit -m 'Add detection for X'`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

---

> ⚠️ **Disclaimer:** PyForensix is for authorized security analysis only. Always obtain explicit permission before scanning systems you do not own or administer.
