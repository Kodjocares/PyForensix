"""
REST API + WebSocket handlers for PyForensix web dashboard.
"""
import os
import platform
import threading
import json
from datetime import datetime
from typing import Any

from flask import Blueprint, jsonify, request
from flask_socketio import emit

from web import socketio

api_bp = Blueprint('api', __name__)

# ── Shared state ──────────────────────────────────────────────────────────────

_scan_cache: dict = {}
_live_alerts: list = []
_MAX_LIVE_ALERTS = 500


def _push_alert(alert: dict):
    """Called from monitor/capture threads — pushes alert to all connected clients."""
    _live_alerts.append(alert)
    if len(_live_alerts) > _MAX_LIVE_ALERTS:
        _live_alerts.pop(0)
    socketio.emit('alert', alert, namespace='/')


def _push_metric(data: dict):
    """Called from LiveMonitor — pushes system metrics to all clients."""
    socketio.emit('metric', data, namespace='/')


# ── WebSocket events ──────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    from forensics.modules.live_monitor import get_monitor
    monitor = get_monitor(on_data=_push_metric, on_alert=_push_alert)
    if not monitor._running:
        monitor.start()
    emit('status', {'message': 'Connected to PyForensix', 'ts': datetime.now().isoformat()})


@socketio.on('start_capture')
def on_start_capture(data):
    iface = data.get('interface')
    from forensics.modules.packet_capture import start_capture, SCAPY_AVAILABLE
    if not SCAPY_AVAILABLE:
        emit('capture_status', {'running': False, 'error': 'scapy not installed. Run: pip install scapy'})
        return
    try:
        start_capture(interface=iface, on_alert=_push_alert)
        emit('capture_status', {'running': True, 'interface': iface or 'default'})
    except Exception as e:
        emit('capture_status', {'running': False, 'error': str(e)})


@socketio.on('stop_capture')
def on_stop_capture():
    from forensics.modules.packet_capture import stop_capture
    stop_capture()
    emit('capture_status', {'running': False})


@socketio.on('request_capture_stats')
def on_capture_stats():
    from forensics.modules.packet_capture import get_capture_session
    session = get_capture_session()
    if session:
        emit('capture_stats', {
            'stats':   session.stats,
            'alerts':  session.alerts[-50:],
            'running': session.is_running,
        })
    else:
        emit('capture_stats', {'stats': {}, 'alerts': [], 'running': False})


# ── REST API: System Info ─────────────────────────────────────────────────────

@api_bp.route('/system')
def system_info():
    from forensics.core.system_info import get_system_info, get_logged_in_users
    return jsonify({
        'info':  get_system_info(),
        'users': get_logged_in_users(),
    })


# ── REST API: Full Scan ───────────────────────────────────────────────────────

@api_bp.route('/scan', methods=['POST'])
def run_full_scan():
    """
    Launch a background full forensic scan.
    Returns immediately with a scan ID; poll /api/scan/<id>/status.
    """
    import uuid
    scan_id = str(uuid.uuid4())[:8]
    _scan_cache[scan_id] = {'status': 'running', 'started': datetime.now().isoformat()}
    threading.Thread(target=_do_scan, args=(scan_id,), daemon=True).start()
    return jsonify({'scan_id': scan_id, 'status': 'running'})


def _do_scan(scan_id: str):
    try:
        from forensics.core.system_info        import get_system_info, get_startup_items
        from forensics.core.process_scanner    import scan_processes
        from forensics.core.network_scanner    import scan_connections, scan_open_ports
        from forensics.core.file_scanner       import scan_recently_modified
        from forensics.core.log_analyzer       import (scan_linux_logs, scan_windows_events,
                                                        summarize_brute_force)
        from forensics.core.intrusion_detector import build_report

        socketio.emit('scan_progress', {'scan_id': scan_id, 'step': 'system_info', 'pct': 5})
        sysinfo  = get_system_info()
        startup  = get_startup_items()

        socketio.emit('scan_progress', {'scan_id': scan_id, 'step': 'processes', 'pct': 20})
        procs    = scan_processes()

        socketio.emit('scan_progress', {'scan_id': scan_id, 'step': 'network', 'pct': 40})
        conns    = scan_connections()
        ports    = scan_open_ports()

        socketio.emit('scan_progress', {'scan_id': scan_id, 'step': 'files', 'pct': 60})
        files    = scan_recently_modified(hours=24)

        socketio.emit('scan_progress', {'scan_id': scan_id, 'step': 'logs', 'pct': 75})
        logs     = scan_linux_logs() if platform.system() != 'Windows' else scan_windows_events()
        brute    = summarize_brute_force(logs)

        socketio.emit('scan_progress', {'scan_id': scan_id, 'step': 'report', 'pct': 90})
        report   = build_report(
            processes=procs, connections=conns, open_ports=ports,
            recent_files=files, log_entries=logs, brute_force=brute, startup=startup,
        )
        rd = report.to_dict()

        result = {
            'status':    'complete',
            'scan_id':   scan_id,
            'system':    sysinfo,
            'report':    rd,
            'processes': [p for p in procs if p['flags']][:50],
            'conns':     [c for c in conns if c['flags']][:50],
            'ports':     ports,
            'files':     [f for f in files if f.get('flags')][:50],
            'logs':      [l for l in logs if l.get('pattern')][:100],
            'brute':     brute,
        }
        _scan_cache[scan_id] = result
        socketio.emit('scan_complete', {'scan_id': scan_id, 'risk_level': rd['risk_level'],
                                         'score': rd['score'], 'summary': rd['summary']})

        # Push critical alerts immediately
        for alert in rd.get('alerts', []):
            if alert.get('severity') in ('CRITICAL', 'HIGH'):
                _push_alert({
                    'type':      f"SCAN_{alert.get('category','FINDING')}",
                    'severity':  alert['severity'],
                    'message':   alert.get('title', ''),
                    'timestamp': datetime.now().isoformat(),
                    'flags':     alert.get('flags', []),
                })

    except Exception as e:
        import traceback
        _scan_cache[scan_id] = {'status': 'error', 'error': str(e), 'trace': traceback.format_exc()}
        socketio.emit('scan_error', {'scan_id': scan_id, 'error': str(e)})


@api_bp.route('/scan/<scan_id>')
def get_scan(scan_id):
    result = _scan_cache.get(scan_id)
    if not result:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(result)


@api_bp.route('/scan/<scan_id>/status')
def scan_status(scan_id):
    result = _scan_cache.get(scan_id, {})
    return jsonify({'status': result.get('status', 'not_found'), 'scan_id': scan_id})


# ── REST API: Processes ───────────────────────────────────────────────────────

@api_bp.route('/processes')
def processes():
    from forensics.core.process_scanner import scan_processes
    return jsonify(scan_processes())


# ── REST API: Network ─────────────────────────────────────────────────────────

@api_bp.route('/network/connections')
def connections():
    from forensics.core.network_scanner import scan_connections
    return jsonify(scan_connections())


@api_bp.route('/network/ports')
def ports():
    from forensics.core.network_scanner import scan_open_ports
    return jsonify(scan_open_ports())


@api_bp.route('/network/interfaces')
def interfaces():
    from forensics.modules.packet_capture import get_interfaces
    return jsonify(get_interfaces())


# ── REST API: YARA ────────────────────────────────────────────────────────────

@api_bp.route('/yara/rules')
def yara_rules():
    from forensics.modules.yara_scanner import get_scanner
    scanner = get_scanner()
    return jsonify({
        'available':  scanner.available,
        'rules':      scanner.get_rule_list(),
        'rule_count': len(scanner.get_rule_list()),
    })


@api_bp.route('/yara/scan', methods=['POST'])
def yara_scan():
    data = request.json or {}
    path = data.get('path', '/')
    max_files = min(int(data.get('max_files', 200)), 1000)
    exts = data.get('extensions')  # e.g. [".exe", ".dll", ".ps1"]

    from forensics.modules.yara_scanner import get_scanner
    scanner = get_scanner()
    if not scanner.available:
        return jsonify({'error': 'yara-python not installed. Run: pip install yara-python'}), 400

    def _do_yara():
        results = scanner.scan_directory(path, max_files=max_files, extensions=exts)
        socketio.emit('yara_results', {
            'path':     path,
            'count':    len(results),
            'matches':  results,
        })

    threading.Thread(target=_do_yara, daemon=True).start()
    return jsonify({'status': 'scanning', 'path': path})


@api_bp.route('/yara/scan-file', methods=['POST'])
def yara_scan_file():
    data = request.json or {}
    path = data.get('path', '')
    if not path or not os.path.isfile(path):
        return jsonify({'error': f'File not found: {path}'}), 400
    from forensics.modules.yara_scanner import get_scanner
    return jsonify(get_scanner().scan_file(path))


# ── REST API: Threat Intelligence ─────────────────────────────────────────────

@api_bp.route('/intel/ip/<ip>')
def intel_ip(ip):
    from forensics.modules.threat_intel import lookup_ip
    return jsonify(lookup_ip(ip))


@api_bp.route('/intel/hash/<file_hash>')
def intel_hash(file_hash):
    from forensics.modules.threat_intel import lookup_hash
    return jsonify(lookup_hash(file_hash))


@api_bp.route('/intel/status')
def intel_status():
    from forensics.modules.threat_intel import get_api_status
    return jsonify(get_api_status())


@api_bp.route('/intel/enrich-scan', methods=['POST'])
def intel_enrich():
    """
    Take IPs from active connections and enrich with threat intel.
    Returns enriched results (may take a while if no API cache).
    """
    from forensics.core.network_scanner import scan_connections
    from forensics.modules.threat_intel import lookup_ip
    import ipaddress

    conns = scan_connections()
    public_ips = set()
    for c in conns:
        rip = c.get('raddr', '').split(':')[0]
        if rip:
            try:
                addr = ipaddress.ip_address(rip)
                if not (addr.is_private or addr.is_loopback):
                    public_ips.add(rip)
            except ValueError:
                pass

    results = []
    for ip in list(public_ips)[:20]:   # Cap at 20 to be polite to APIs
        results.append(lookup_ip(ip))

    return jsonify({'enriched': results, 'count': len(results)})


# ── REST API: Live alerts ─────────────────────────────────────────────────────

@api_bp.route('/alerts')
def get_alerts():
    limit = int(request.args.get('limit', 100))
    return jsonify(_live_alerts[-limit:])


# ── REST API: Reports ─────────────────────────────────────────────────────────

@api_bp.route('/report/<scan_id>/html')
def report_html(scan_id):
    from flask import make_response
    from forensics.utils.reporter import generate_html_report
    import tempfile

    result = _scan_cache.get(scan_id)
    if not result or result.get('status') != 'complete':
        return jsonify({'error': 'Scan not complete or not found'}), 404

    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tmp:
        path = generate_html_report(result['report'], result.get('system', {}), tmp.name)

    with open(path, 'rb') as f:
        content = f.read()
    os.unlink(path)

    resp = make_response(content)
    resp.headers['Content-Type'] = 'text/html'
    resp.headers['Content-Disposition'] = f'attachment; filename=pyforensix_{scan_id}.html'
    return resp


@api_bp.route('/report/<scan_id>/json')
def report_json(scan_id):
    from flask import make_response
    result = _scan_cache.get(scan_id)
    if not result or result.get('status') != 'complete':
        return jsonify({'error': 'Scan not complete or not found'}), 404
    resp = make_response(json.dumps(result, indent=2, default=str))
    resp.headers['Content-Type'] = 'application/json'
    resp.headers['Content-Disposition'] = f'attachment; filename=pyforensix_{scan_id}.json'
    return resp
