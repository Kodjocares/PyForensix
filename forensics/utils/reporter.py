"""
Reporter — generates HTML, JSON, and CSV forensic reports from scan results.
"""
import json
import csv
import os
from datetime import datetime
from typing import Dict, Any, List

SEVERITY_COLOR = {
    'CRITICAL': '#FF4757',
    'HIGH':     '#FF6B35',
    'MEDIUM':   '#FFA502',
    'LOW':      '#2ED573',
    'CLEAN':    '#2ED573',
    'OK':       '#2ED573',
    'INFO':     '#70A1FF',
}

RISK_BADGE = {
    'CRITICAL': '#FF4757',
    'HIGH':     '#FF6B35',
    'MEDIUM':   '#FFA502',
    'LOW':      '#2ED573',
    'CLEAN':    '#2ED573',
}


def _severity_badge(sev: str) -> str:
    color = SEVERITY_COLOR.get(sev, '#ccc')
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700">{sev}</span>'


def generate_html_report(report_dict: Dict[str, Any], system_info: Dict[str, Any], output_path: str = '') -> str:
    """Generate a full-page HTML forensic report."""
    if not output_path:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f'pyforensix_report_{ts}.html'

    alerts = report_dict.get('alerts', [])
    summary = report_dict.get('summary', {})
    risk = report_dict.get('risk_level', 'UNKNOWN')
    score = report_dict.get('score', 0)
    scan_time = report_dict.get('scan_time', '')

    risk_color = RISK_BADGE.get(risk, '#ccc')

    # Group alerts by category
    categories: Dict[str, List] = {}
    for alert in alerts:
        cat = alert.get('category', 'OTHER')
        categories.setdefault(cat, []).append(alert)

    def alert_rows():
        rows = []
        for cat, cat_alerts in categories.items():
            rows.append(f'<tr><td colspan="4" style="background:#1a1f2e;padding:8px 12px;color:#70A1FF;font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:1px">{cat}</td></tr>')
            for a in sorted(cat_alerts, key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW','OK'].index(x.get('severity','OK')) if x.get('severity','OK') in ['CRITICAL','HIGH','MEDIUM','LOW','OK'] else 5):
                sev = a.get('severity','OK')
                sc = SEVERITY_COLOR.get(sev,'#ccc')
                techs = ', '.join(f"{t['id']}: {t['name']}" for t in a.get('techniques',[]))
                rems = '<br>'.join(f"• {r}" for r in a.get('remediation',[]) if r)
                flags = ', '.join(f'<code style="font-size:10px;background:#1a1f2e;padding:1px 4px;border-radius:2px">{f}</code>' for f in a.get('flags',[]))
                rows.append(f'''
                <tr style="border-bottom:1px solid #2a2f3e">
                  <td style="padding:10px 12px;vertical-align:top;white-space:nowrap">
                    <span style="background:{sc};color:#fff;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700">{sev}</span>
                  </td>
                  <td style="padding:10px 12px;vertical-align:top">
                    <div style="font-weight:600;margin-bottom:4px;color:#e0e0e0">{a.get("title","")}</div>
                    <div style="color:#888;font-size:12px">{a.get("detail","")}</div>
                    <div style="margin-top:6px">{flags}</div>
                  </td>
                  <td style="padding:10px 12px;vertical-align:top;font-size:11px;color:#70A1FF">{techs}</td>
                  <td style="padding:10px 12px;vertical-align:top;font-size:11px;color:#aaa">{rems}</td>
                </tr>''')
        return '\n'.join(rows)

    def sys_rows():
        rows = []
        skip = {'disks', 'scan_time'}
        for k, v in system_info.items():
            if k in skip or isinstance(v, list):
                continue
            rows.append(f'<tr><td style="padding:6px 12px;color:#888;font-size:12px">{k.replace("_"," ").title()}</td><td style="padding:6px 12px;color:#e0e0e0;font-size:12px">{v}</td></tr>')
        return '\n'.join(rows)

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PyForensix — Forensic Report {scan_time}</title>
<style>
  body {{ margin:0; font-family:'Courier New', monospace; background:#0d1117; color:#c9d1d9; }}
  .header {{ background:#161b22; border-bottom:1px solid #30363d; padding:24px 32px; display:flex; align-items:center; justify-content:space-between; }}
  .logo {{ font-size:22px; font-weight:700; color:#58a6ff; letter-spacing:2px; }}
  .meta {{ font-size:12px; color:#8b949e; }}
  .risk-badge {{ font-size:18px; font-weight:700; padding:6px 18px; border-radius:6px; background:{risk_color}; color:#fff; }}
  .section {{ margin:24px 32px; }}
  .section-title {{ font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:1.5px; color:#58a6ff; margin-bottom:12px; border-bottom:1px solid #21262d; padding-bottom:8px; }}
  .card-row {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:24px; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px 20px; }}
  .card-value {{ font-size:28px; font-weight:700; margin-bottom:4px; }}
  .card-label {{ font-size:11px; color:#8b949e; text-transform:uppercase; letter-spacing:1px; }}
  table {{ width:100%; border-collapse:collapse; background:#161b22; border:1px solid #30363d; border-radius:8px; overflow:hidden; }}
  th {{ background:#21262d; padding:10px 12px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#8b949e; }}
  tr:hover td {{ background:#1c2128; }}
  code {{ font-family:'Courier New', monospace; }}
  .footer {{ text-align:center; padding:24px; font-size:11px; color:#484f58; border-top:1px solid #21262d; }}
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="logo">⚡ PyForensix</div>
    <div class="meta">System Forensics &amp; Intrusion Detection Report</div>
    <div class="meta">Generated: {scan_time} | Host: {system_info.get('hostname','N/A')} | OS: {system_info.get('os','N/A')} {system_info.get('os_release','')}</div>
  </div>
  <div>
    <span class="risk-badge">RISK: {risk}</span>
    <div class="meta" style="text-align:right;margin-top:6px">Threat Score: {score}</div>
  </div>
</div>

<div class="section">
  <div class="section-title">Executive Summary</div>
  <div class="card-row">
    <div class="card"><div class="card-value" style="color:#FF4757">{summary.get("CRITICAL",0)}</div><div class="card-label">Critical</div></div>
    <div class="card"><div class="card-value" style="color:#FF6B35">{summary.get("HIGH",0)}</div><div class="card-label">High</div></div>
    <div class="card"><div class="card-value" style="color:#FFA502">{summary.get("MEDIUM",0)}</div><div class="card-label">Medium</div></div>
    <div class="card"><div class="card-value" style="color:#2ED573">{summary.get("LOW",0)}</div><div class="card-label">Low</div></div>
  </div>
</div>

<div class="section">
  <div class="section-title">Alerts &amp; Findings</div>
  <table>
    <thead><tr>
      <th>Severity</th><th>Finding</th><th>MITRE ATT&amp;CK</th><th>Remediation</th>
    </tr></thead>
    <tbody>{alert_rows()}</tbody>
  </table>
</div>

<div class="section">
  <div class="section-title">System Information</div>
  <table><tbody>{sys_rows()}</tbody></table>
</div>

<div class="footer">PyForensix — Open-source Forensics Toolkit | Report generated {scan_time}</div>
</body></html>'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return output_path


def generate_json_report(report_dict: Dict, system_info: Dict, output_path: str = '') -> str:
    if not output_path:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f'pyforensix_report_{ts}.json'
    with open(output_path, 'w') as f:
        json.dump({'system': system_info, 'report': report_dict}, f, indent=2, default=str)
    return output_path


def generate_csv_report(alerts: List[Dict], output_path: str = '') -> str:
    if not output_path:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f'pyforensix_alerts_{ts}.csv'
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Severity', 'Category', 'Title', 'Detail', 'Flags', 'MITRE Techniques'])
        for a in alerts:
            writer.writerow([
                a.get('severity', ''),
                a.get('category', ''),
                a.get('title', ''),
                a.get('detail', ''),
                ' | '.join(a.get('flags', [])),
                ' | '.join(f"{t['id']}" for t in a.get('techniques', [])),
            ])
    return output_path
