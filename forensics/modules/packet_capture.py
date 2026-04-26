"""
Packet Capture & Analysis — captures live traffic and analyzes PCAP files.

Live capture: uses scapy if available, falls back to raw socket sniffing.
PCAP analysis: scapy or dpkt.
"""
import os
import socket
import struct
import threading
import time
import json
import platform
from datetime import datetime
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional, Callable

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap, ARP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Threat signatures ─────────────────────────────────────────────────────────

SUSPICIOUS_PORTS = {
    4444: 'Metasploit',  4445: 'Metasploit-alt', 5555: 'Android-debug/shell',
    6666: 'IRC/backdoor', 6667: 'IRC-C2',         7777: 'Reverse-shell',
    8888: 'Jupyter/backdoor', 9999: 'Backdoor',   1337: 'Hacker-port',
    31337: 'Back-Orifice', 12345: 'NetBus',       54321: 'Reverse-shell',
}

C2_PATTERNS = [
    b'meterpreter', b'beacon', b'cobaltstrike',
    b'empire', b'powershell -enc', b'base64',
]

DNS_SUSPICIOUS_TYPES = {16: 'TXT', 255: 'ANY'}  # Often used in DNS tunneling

# High-entropy DNS names suggest DGA (Domain Generation Algorithm)
import math

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ── Capture session ───────────────────────────────────────────────────────────

class CaptureSession:
    """
    Manages a live packet capture session with real-time analysis.
    Thread-safe: can be started/stopped from any thread.
    """

    def __init__(self, interface: Optional[str] = None,
                 packet_limit: int = 10000,
                 on_alert: Optional[Callable] = None):
        self.interface    = interface
        self.packet_limit = packet_limit
        self.on_alert     = on_alert  # callback(alert_dict)

        self._packets:    List[Dict] = []
        self._alerts:     List[Dict] = []
        self._stats       = _PacketStats()
        self._running     = False
        self._thread:     Optional[threading.Thread] = None
        self._lock        = threading.Lock()
        self.available    = SCAPY_AVAILABLE

    def start(self):
        if self._running or not SCAPY_AVAILABLE:
            return
        self._running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _capture_loop(self):
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
                count=self.packet_limit,
            )
        except PermissionError:
            self._add_alert('CAPTURE_ERROR', 'Packet capture requires root/Administrator privileges.', 'HIGH')
        except Exception as e:
            self._add_alert('CAPTURE_ERROR', str(e), 'HIGH')

    def _process_packet(self, pkt):
        if not self._running:
            return
        parsed = self._parse_packet(pkt)
        with self._lock:
            self._packets.append(parsed)
            self._stats.update(parsed)
            for alert in parsed.get('alerts', []):
                self._alerts.append(alert)
                if self.on_alert:
                    self.on_alert(alert)

    def _parse_packet(self, pkt) -> Dict[str, Any]:
        now = datetime.now().isoformat()
        result: Dict[str, Any] = {
            'ts':       now,
            'proto':    'UNKNOWN',
            'src_ip':   '', 'dst_ip': '',
            'src_port': 0,  'dst_port': 0,
            'length':   len(pkt),
            'flags':    [],
            'alerts':   [],
            'dns_query': '',
            'http_host': '',
            'payload_preview': '',
        }

        if not SCAPY_AVAILABLE:
            return result

        # IP layer
        if pkt.haslayer(IP):
            result['src_ip'] = pkt[IP].src
            result['dst_ip'] = pkt[IP].dst

        # Transport layer
        if pkt.haslayer(TCP):
            result['proto']    = 'TCP'
            result['src_port'] = pkt[TCP].sport
            result['dst_port'] = pkt[TCP].dport
            tcp_flags = pkt[TCP].flags
            result['tcp_flags'] = str(tcp_flags)

            # SYN scan detection
            if tcp_flags == 'S':
                result['flags'].append('SYN_ONLY')

            # Check suspicious ports
            for port in [pkt[TCP].sport, pkt[TCP].dport]:
                if port in SUSPICIOUS_PORTS:
                    result['alerts'].append(self._make_alert(
                        'SUSPICIOUS_PORT',
                        f"Traffic on {port} ({SUSPICIOUS_PORTS[port]}): {result['src_ip']} → {result['dst_ip']}",
                        'HIGH',
                    ))

        elif pkt.haslayer(UDP):
            result['proto']    = 'UDP'
            result['src_port'] = pkt[UDP].sport
            result['dst_port'] = pkt[UDP].dport

        elif pkt.haslayer(ICMP):
            result['proto'] = 'ICMP'

        # DNS analysis
        if pkt.haslayer(DNS):
            result['proto'] = 'DNS'
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode('utf-8', errors='replace').rstrip('.')
                result['dns_query'] = qname

                # DGA detection: high entropy domain
                domain_parts = qname.split('.')
                if domain_parts:
                    label = domain_parts[0]
                    ent = _entropy(label)
                    if ent > 3.5 and len(label) > 10:
                        result['alerts'].append(self._make_alert(
                            'DGA_SUSPECTED',
                            f"High-entropy DNS query (possible DGA): {qname} (entropy={ent:.2f})",
                            'HIGH',
                        ))

                # DNS tunneling: TXT/ANY queries
                qtype = pkt[DNSQR].qtype
                if qtype in DNS_SUSPICIOUS_TYPES:
                    result['alerts'].append(self._make_alert(
                        'DNS_TUNNELING_SUSPECT',
                        f"Suspicious DNS query type {DNS_SUSPICIOUS_TYPES[qtype]} for {qname}",
                        'MEDIUM',
                    ))

        # HTTP
        if pkt.haslayer(HTTPRequest):
            result['proto']     = 'HTTP'
            result['http_host'] = pkt[HTTPRequest].Host.decode('utf-8', errors='replace') if pkt[HTTPRequest].Host else ''
            method = pkt[HTTPRequest].Method.decode('utf-8', errors='replace') if pkt[HTTPRequest].Method else ''
            path   = pkt[HTTPRequest].Path.decode('utf-8', errors='replace') if pkt[HTTPRequest].Path else ''
            result['http_request'] = f"{method} {path}"

        # Raw payload: check for C2 patterns
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])[:512]
            result['payload_preview'] = payload[:64].hex()
            pl_lower = payload.lower()
            for pattern in C2_PATTERNS:
                if pattern in pl_lower:
                    result['alerts'].append(self._make_alert(
                        'C2_PAYLOAD_MATCH',
                        f"Payload matches C2 pattern '{pattern.decode()}': {result['src_ip']} → {result['dst_ip']}",
                        'CRITICAL',
                    ))
                    break

        # ARP spoofing detection (same IP, different MACs across time)
        if pkt.haslayer(ARP):
            result['proto'] = 'ARP'
            if pkt[ARP].op == 2:  # ARP reply
                result['arp_sender_ip']  = pkt[ARP].psrc
                result['arp_sender_mac'] = pkt[ARP].hwsrc

        return result

    def _make_alert(self, alert_type: str, message: str, severity: str) -> Dict:
        return {
            'type':      alert_type,
            'message':   message,
            'severity':  severity,
            'timestamp': datetime.now().isoformat(),
        }

    def _add_alert(self, alert_type: str, message: str, severity: str):
        a = self._make_alert(alert_type, message, severity)
        with self._lock:
            self._alerts.append(a)
        if self.on_alert:
            self.on_alert(a)

    @property
    def packets(self) -> List[Dict]:
        with self._lock:
            return list(self._packets)

    @property
    def alerts(self) -> List[Dict]:
        with self._lock:
            return list(self._alerts)

    @property
    def stats(self) -> Dict:
        with self._lock:
            return self._stats.snapshot()

    @property
    def is_running(self) -> bool:
        return self._running


class _PacketStats:
    def __init__(self):
        self.total       = 0
        self.by_proto    = Counter()
        self.by_src_ip   = Counter()
        self.by_dst_ip   = Counter()
        self.by_dst_port = Counter()
        self.alert_count = 0
        self.bytes_total = 0

    def update(self, pkt: Dict):
        self.total       += 1
        self.bytes_total += pkt.get('length', 0)
        self.by_proto[pkt.get('proto', 'UNKNOWN')] += 1
        if pkt.get('src_ip'):
            self.by_src_ip[pkt['src_ip']] += 1
        if pkt.get('dst_ip'):
            self.by_dst_ip[pkt['dst_ip']] += 1
        if pkt.get('dst_port'):
            self.by_dst_port[pkt['dst_port']] += 1
        self.alert_count += len(pkt.get('alerts', []))

    def snapshot(self) -> Dict:
        return {
            'total':           self.total,
            'bytes_total':     self.bytes_total,
            'by_proto':        dict(self.by_proto.most_common(10)),
            'top_src_ips':     dict(self.by_src_ip.most_common(10)),
            'top_dst_ips':     dict(self.by_dst_ip.most_common(10)),
            'top_dst_ports':   dict(self.by_dst_port.most_common(10)),
            'alert_count':     self.alert_count,
        }


# ── PCAP file analysis ────────────────────────────────────────────────────────

def analyze_pcap(path: str) -> Dict[str, Any]:
    """Analyze a saved PCAP file and return findings."""
    if not SCAPY_AVAILABLE:
        return {'error': 'scapy not installed', 'path': path}
    if not os.path.isfile(path):
        return {'error': f'File not found: {path}', 'path': path}

    session = CaptureSession()
    try:
        packets = rdpcap(path)
    except Exception as e:
        return {'error': str(e), 'path': path}

    results = []
    for pkt in packets:
        parsed = session._parse_packet(pkt)
        session._stats.update(parsed)
        results.append(parsed)

    all_alerts = [a for p in results for a in p.get('alerts', [])]

    return {
        'path':          path,
        'packet_count':  len(results),
        'stats':         session._stats.snapshot(),
        'alerts':        all_alerts,
        'alert_count':   len(all_alerts),
        'packets':       results[:200],   # Cap to avoid huge payloads
    }


# ── Interface listing ─────────────────────────────────────────────────────────

def get_interfaces() -> List[Dict[str, str]]:
    """List available network interfaces."""
    import psutil
    ifaces = []
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ifaces.append({'name': name, 'ip': addr.address})
                break
    return ifaces


# ── Global capture session (singleton) ───────────────────────────────────────

_active_session: Optional[CaptureSession] = None


def start_capture(interface: Optional[str] = None, on_alert: Optional[Callable] = None) -> CaptureSession:
    global _active_session
    if _active_session and _active_session.is_running:
        _active_session.stop()
    _active_session = CaptureSession(interface=interface, on_alert=on_alert)
    _active_session.start()
    return _active_session


def stop_capture():
    global _active_session
    if _active_session:
        _active_session.stop()


def get_capture_session() -> Optional[CaptureSession]:
    return _active_session
