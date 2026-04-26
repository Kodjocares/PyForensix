"""
Live Monitor — polls system metrics in real-time and fires callbacks.
Designed to feed Flask-SocketIO for the live dashboard.
"""
import psutil
import time
import threading
import platform
import os
from datetime import datetime
from typing import Callable, Optional, Dict, Any, List
from collections import deque

MAX_HISTORY = 60  # Keep 60 data points (60s at 1s interval)


class LiveMonitor:
    """
    Background thread that collects system metrics at a configurable interval
    and fires a callback with the latest snapshot.

    Usage:
        monitor = LiveMonitor(on_data=my_callback, interval=2)
        monitor.start()
        ...
        monitor.stop()
    """

    def __init__(self, on_data: Optional[Callable] = None,
                 on_alert: Optional[Callable] = None,
                 interval: float = 2.0):
        self.on_data   = on_data   # callback(snapshot_dict)
        self.on_alert  = on_alert  # callback(alert_dict)
        self.interval  = interval
        self._running  = False
        self._thread:  Optional[threading.Thread] = None

        # Rolling history for sparklines
        self._cpu_history    = deque(maxlen=MAX_HISTORY)
        self._mem_history    = deque(maxlen=MAX_HISTORY)
        self._net_sent_hist  = deque(maxlen=MAX_HISTORY)
        self._net_recv_hist  = deque(maxlen=MAX_HISTORY)

        # Previous net counters (for per-second delta)
        self._prev_net = psutil.net_io_counters()
        self._prev_ts  = time.time()

        # Track new processes (appear between polls)
        self._known_pids: set = set(p.pid for p in psutil.process_iter(['pid']))

        # Alert thresholds
        self.cpu_alert_threshold  = 90.0   # %
        self.mem_alert_threshold  = 90.0   # %
        self.disk_alert_threshold = 95.0   # %

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while self._running:
            try:
                snap = self._collect()
                self._cpu_history.append(snap['cpu_pct'])
                self._mem_history.append(snap['mem_pct'])
                self._net_sent_hist.append(snap['net_sent_bps'])
                self._net_recv_hist.append(snap['net_recv_bps'])

                snap['cpu_history']       = list(self._cpu_history)
                snap['mem_history']       = list(self._mem_history)
                snap['net_sent_history']  = list(self._net_sent_hist)
                snap['net_recv_history']  = list(self._net_recv_hist)

                if self.on_data:
                    self.on_data(snap)

                self._check_alerts(snap)
            except Exception:
                pass
            time.sleep(self.interval)

    def _collect(self) -> Dict[str, Any]:
        now = time.time()
        cpu  = psutil.cpu_percent(interval=None)
        mem  = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net  = psutil.net_io_counters()

        dt = max(now - self._prev_ts, 0.001)
        sent_bps = (net.bytes_sent - self._prev_net.bytes_sent) / dt
        recv_bps = (net.bytes_recv - self._prev_net.bytes_recv) / dt
        self._prev_net = net
        self._prev_ts  = now

        # Top 5 processes by CPU
        top_procs = []
        for p in sorted(
            psutil.process_iter(['pid','name','cpu_percent','memory_percent','status']),
            key=lambda x: x.info.get('cpu_percent') or 0,
            reverse=True
        )[:5]:
            try:
                top_procs.append({
                    'pid':      p.info['pid'],
                    'name':     p.info['name'],
                    'cpu_pct':  round(p.info['cpu_percent'] or 0, 1),
                    'mem_pct':  round(p.info['memory_percent'] or 0, 1),
                    'status':   p.info['status'],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # New processes since last poll
        current_pids = set(p.pid for p in psutil.process_iter(['pid']))
        new_pids = current_pids - self._known_pids
        new_procs = []
        for pid in new_pids:
            try:
                p = psutil.Process(pid)
                new_procs.append({
                    'pid':  pid,
                    'name': p.name(),
                    'exe':  p.exe() or '',
                    'user': p.username(),
                    'cmd':  ' '.join(p.cmdline())[:120],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        self._known_pids = current_pids

        # Active connections count
        try:
            conn_count = len(psutil.net_connections())
        except Exception:
            conn_count = 0

        return {
            'timestamp':       datetime.now().isoformat(),
            'cpu_pct':         round(cpu, 1),
            'cpu_count':       psutil.cpu_count(),
            'mem_pct':         round(mem.percent, 1),
            'mem_used_gb':     round(mem.used / 1e9, 2),
            'mem_total_gb':    round(mem.total / 1e9, 2),
            'disk_pct':        round(disk.percent, 1),
            'disk_used_gb':    round(disk.used / 1e9, 2),
            'disk_total_gb':   round(disk.total / 1e9, 2),
            'net_sent_bps':    round(sent_bps),
            'net_recv_bps':    round(recv_bps),
            'net_sent_mb':     round(net.bytes_sent / 1e6, 2),
            'net_recv_mb':     round(net.bytes_recv / 1e6, 2),
            'conn_count':      conn_count,
            'top_processes':   top_procs,
            'new_processes':   new_procs,
        }

    def _check_alerts(self, snap: Dict):
        if not self.on_alert:
            return
        if snap['cpu_pct'] >= self.cpu_alert_threshold:
            self.on_alert({'type': 'CPU_SPIKE', 'severity': 'HIGH',
                           'message': f"CPU at {snap['cpu_pct']}% (threshold: {self.cpu_alert_threshold}%)",
                           'timestamp': snap['timestamp']})
        if snap['mem_pct'] >= self.mem_alert_threshold:
            self.on_alert({'type': 'MEMORY_HIGH', 'severity': 'HIGH',
                           'message': f"Memory at {snap['mem_pct']}% (threshold: {self.mem_alert_threshold}%)",
                           'timestamp': snap['timestamp']})
        if snap['disk_pct'] >= self.disk_alert_threshold:
            self.on_alert({'type': 'DISK_CRITICAL', 'severity': 'CRITICAL',
                           'message': f"Disk at {snap['disk_pct']}% (threshold: {self.disk_alert_threshold}%)",
                           'timestamp': snap['timestamp']})
        for proc in snap.get('new_processes', []):
            self.on_alert({'type': 'NEW_PROCESS', 'severity': 'MEDIUM',
                           'message': f"New process spawned: {proc['name']} (PID {proc['pid']}) — {proc['cmd'][:80]}",
                           'timestamp': snap['timestamp'],
                           'detail': proc})


# ── Singleton ──────────────────────────────────────────────────────────────────

_monitor: Optional[LiveMonitor] = None


def get_monitor(on_data: Optional[Callable] = None,
                on_alert: Optional[Callable] = None) -> LiveMonitor:
    global _monitor
    if _monitor is None:
        _monitor = LiveMonitor(on_data=on_data, on_alert=on_alert)
    else:
        if on_data:
            _monitor.on_data = on_data
        if on_alert:
            _monitor.on_alert = on_alert
    return _monitor
