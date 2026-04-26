"""
Threat Intelligence — enriches IPs and file hashes via free public APIs.

Supported sources:
  • AbuseIPDB   — IP reputation (free tier: 1000 req/day)
  • VirusTotal  — IP + hash reputation (free tier: 4 req/min)
  • MalwareBazaar — hash lookup (no key required)
  • Shodan      — IP exposure (free tier)

API keys are read from environment variables (never hardcoded).
Set them in a .env file or export before running:
  export ABUSEIPDB_KEY=your_key
  export VIRUSTOTAL_KEY=your_key
  export SHODAN_KEY=your_key
"""
import os
import json
import time
import hashlib
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

# ── API keys (from environment) ───────────────────────────────────────────────

def _key(name: str) -> str:
    return os.environ.get(name, '')


# ── Simple in-memory cache ────────────────────────────────────────────────────

class _Cache:
    def __init__(self, ttl_seconds: int = 3600):
        self._store: Dict[str, Dict] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if not entry:
            return None
        if time.time() - entry['ts'] > self._ttl:
            del self._store[key]
            return None
        return entry['data']

    def set(self, key: str, data: Any):
        self._store[key] = {'ts': time.time(), 'data': data}

    def clear(self):
        self._store.clear()


_cache = _Cache(ttl_seconds=3600)


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _get(url: str, headers: Dict[str, str] = None, timeout: int = 8) -> Optional[Dict]:
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {'_http_error': e.code, '_reason': str(e.reason)}
    except Exception as e:
        return {'_error': str(e)}


def _post(url: str, data: bytes, headers: Dict[str, str] = None, timeout: int = 8) -> Optional[Dict]:
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method='POST')
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {'_error': str(e)}


# ── IP Reputation ─────────────────────────────────────────────────────────────

def lookup_ip_abuseipdb(ip: str) -> Dict[str, Any]:
    """Check IP reputation via AbuseIPDB. Requires ABUSEIPDB_KEY."""
    cache_key = f'abuse:{ip}'
    cached = _cache.get(cache_key)
    if cached:
        return cached

    key = _key('ABUSEIPDB_KEY')
    if not key:
        return {'source': 'AbuseIPDB', 'error': 'No API key (set ABUSEIPDB_KEY)', 'ip': ip}

    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90&verbose'
    raw = _get(url, headers={'Key': key, 'Accept': 'application/json'})

    if not raw or '_error' in raw:
        return {'source': 'AbuseIPDB', 'error': raw.get('_error', 'Unknown'), 'ip': ip}

    d = raw.get('data', {})
    result = {
        'source':           'AbuseIPDB',
        'ip':               ip,
        'abuse_score':      d.get('abuseConfidenceScore', 0),
        'total_reports':    d.get('totalReports', 0),
        'country':          d.get('countryCode', ''),
        'isp':              d.get('isp', ''),
        'domain':           d.get('domain', ''),
        'is_tor':           d.get('isTor', False),
        'is_public':        d.get('isPublic', True),
        'last_reported':    d.get('lastReportedAt', ''),
        'threat_level':     _abuse_level(d.get('abuseConfidenceScore', 0)),
        'usage_type':       d.get('usageType', ''),
    }
    _cache.set(cache_key, result)
    return result


def lookup_ip_virustotal(ip: str) -> Dict[str, Any]:
    """Check IP reputation via VirusTotal. Requires VIRUSTOTAL_KEY."""
    cache_key = f'vt_ip:{ip}'
    cached = _cache.get(cache_key)
    if cached:
        return cached

    key = _key('VIRUSTOTAL_KEY')
    if not key:
        return {'source': 'VirusTotal', 'error': 'No API key (set VIRUSTOTAL_KEY)', 'ip': ip}

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip)}'
    raw = _get(url, headers={'x-apikey': key})

    if not raw or '_error' in raw:
        return {'source': 'VirusTotal', 'error': raw.get('_error', 'Unknown'), 'ip': ip}

    attrs = raw.get('data', {}).get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})
    result = {
        'source':       'VirusTotal',
        'ip':           ip,
        'malicious':    stats.get('malicious', 0),
        'suspicious':   stats.get('suspicious', 0),
        'harmless':     stats.get('harmless', 0),
        'undetected':   stats.get('undetected', 0),
        'country':      attrs.get('country', ''),
        'asn':          attrs.get('asn', ''),
        'as_owner':     attrs.get('as_owner', ''),
        'reputation':   attrs.get('reputation', 0),
        'threat_level': 'CRITICAL' if stats.get('malicious', 0) >= 5
                        else 'HIGH' if stats.get('malicious', 0) >= 1
                        else 'MEDIUM' if stats.get('suspicious', 0) >= 3
                        else 'OK',
    }
    _cache.set(cache_key, result)
    return result


def lookup_ip(ip: str) -> Dict[str, Any]:
    """Run IP through all available sources and merge results."""
    # Validate
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {'ip': ip, 'error': 'Invalid IP address'}

    # Skip private/loopback
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return {'ip': ip, 'is_private': True, 'threat_level': 'OK', 'note': 'Private/internal address'}
    except Exception:
        pass

    results = {'ip': ip, 'sources': {}, 'threat_level': 'OK', 'timestamp': datetime.now().isoformat()}

    # AbuseIPDB
    abuse = lookup_ip_abuseipdb(ip)
    results['sources']['abuseipdb'] = abuse
    if 'error' not in abuse:
        results['country'] = abuse.get('country', '')
        results['isp']     = abuse.get('isp', '')
        results['is_tor']  = abuse.get('is_tor', False)

    # VirusTotal
    vt = lookup_ip_virustotal(ip)
    results['sources']['virustotal'] = vt

    # Determine overall threat level
    levels = []
    for src in results['sources'].values():
        lvl = src.get('threat_level', 'OK')
        if lvl and 'error' not in src:
            levels.append(lvl)

    order = ['OK', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    if levels:
        results['threat_level'] = max(levels, key=lambda l: order.index(l) if l in order else 0)

    return results


# ── Hash / File Reputation ────────────────────────────────────────────────────

def lookup_hash_virustotal(file_hash: str) -> Dict[str, Any]:
    """Check file hash reputation via VirusTotal. Requires VIRUSTOTAL_KEY."""
    cache_key = f'vt_hash:{file_hash}'
    cached = _cache.get(cache_key)
    if cached:
        return cached

    key = _key('VIRUSTOTAL_KEY')
    if not key:
        return {'source': 'VirusTotal', 'error': 'No API key (set VIRUSTOTAL_KEY)', 'hash': file_hash}

    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    raw = _get(url, headers={'x-apikey': key})

    if not raw or '_http_error' in raw:
        code = raw.get('_http_error')
        if code == 404:
            return {'source': 'VirusTotal', 'hash': file_hash, 'found': False, 'threat_level': 'OK'}
        return {'source': 'VirusTotal', 'error': str(raw), 'hash': file_hash}

    attrs = raw.get('data', {}).get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})
    result = {
        'source':        'VirusTotal',
        'hash':          file_hash,
        'found':         True,
        'malicious':     stats.get('malicious', 0),
        'suspicious':    stats.get('suspicious', 0),
        'harmless':      stats.get('harmless', 0),
        'undetected':    stats.get('undetected', 0),
        'name':          attrs.get('meaningful_name', ''),
        'type':          attrs.get('type_description', ''),
        'size':          attrs.get('size', 0),
        'first_seen':    attrs.get('first_submission_date', ''),
        'last_seen':     attrs.get('last_submission_date', ''),
        'threat_names':  list(set(
            v.get('result', '') for v in attrs.get('last_analysis_results', {}).values()
            if v.get('category') == 'malicious' and v.get('result')
        ))[:5],
        'threat_level': 'CRITICAL' if stats.get('malicious', 0) >= 5
                        else 'HIGH'   if stats.get('malicious', 0) >= 1
                        else 'MEDIUM' if stats.get('suspicious', 0) >= 3
                        else 'OK',
    }
    _cache.set(cache_key, result)
    return result


def lookup_hash_malwarebazaar(file_hash: str) -> Dict[str, Any]:
    """Check file hash against MalwareBazaar (no API key required)."""
    cache_key = f'mb:{file_hash}'
    cached = _cache.get(cache_key)
    if cached:
        return cached

    url = 'https://mb-api.abuse.ch/api/v1/'
    data = urllib.parse.urlencode({'query': 'get_info', 'hash': file_hash}).encode()
    raw = _post(url, data, headers={'Content-Type': 'application/x-www-form-urlencoded'})

    if not raw or '_error' in raw:
        return {'source': 'MalwareBazaar', 'error': raw.get('_error', 'Unknown'), 'hash': file_hash}

    if raw.get('query_status') == 'hash_not_found':
        result = {'source': 'MalwareBazaar', 'hash': file_hash, 'found': False, 'threat_level': 'OK'}
    else:
        info = raw.get('data', [{}])[0] if raw.get('data') else {}
        result = {
            'source':       'MalwareBazaar',
            'hash':         file_hash,
            'found':        True,
            'file_name':    info.get('file_name', ''),
            'file_type':    info.get('file_type', ''),
            'file_size':    info.get('file_size', 0),
            'first_seen':   info.get('first_seen', ''),
            'signature':    info.get('signature', ''),
            'tags':         info.get('tags', []),
            'reporter':     info.get('reporter', ''),
            'threat_level': 'CRITICAL',
        }

    _cache.set(cache_key, result)
    return result


def lookup_hash(file_hash: str) -> Dict[str, Any]:
    """Run file hash through all available sources."""
    results = {
        'hash':         file_hash,
        'sources':      {},
        'threat_level': 'OK',
        'timestamp':    datetime.now().isoformat(),
    }

    vt = lookup_hash_virustotal(file_hash)
    results['sources']['virustotal'] = vt

    mb = lookup_hash_malwarebazaar(file_hash)
    results['sources']['malwarebazaar'] = mb

    # Determine overall level
    levels = [s.get('threat_level', 'OK') for s in results['sources'].values()
              if 'error' not in s]
    order = ['OK', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    if levels:
        results['threat_level'] = max(levels, key=lambda l: order.index(l) if l in order else 0)

    if results['threat_level'] != 'OK':
        results['known_malicious'] = True
        results['detection_names'] = vt.get('threat_names', [])
        results['malware_family']  = mb.get('signature', '')

    return results


# ── Bulk enrichment ───────────────────────────────────────────────────────────

def enrich_ips(ips: List[str], delay: float = 0.5) -> List[Dict[str, Any]]:
    """Enrich a list of IPs with threat intelligence (rate-limited)."""
    results = []
    seen = set()
    for ip in ips:
        if ip in seen:
            continue
        seen.add(ip)
        results.append(lookup_ip(ip))
        time.sleep(delay)
    return results


def enrich_hashes(hashes: List[str], delay: float = 15.0) -> List[Dict[str, Any]]:
    """
    Enrich a list of file hashes (rate-limited to respect VirusTotal free tier:
    4 requests/min → 15s delay per hash).
    """
    results = []
    seen = set()
    for h in hashes:
        if h in seen or not h:
            continue
        seen.add(h)
        results.append(lookup_hash(h))
        time.sleep(delay)
    return results


# ── Helpers ───────────────────────────────────────────────────────────────────

def _abuse_level(score: int) -> str:
    if score >= 80:
        return 'CRITICAL'
    elif score >= 50:
        return 'HIGH'
    elif score >= 20:
        return 'MEDIUM'
    elif score > 0:
        return 'LOW'
    return 'OK'


def get_api_status() -> Dict[str, Any]:
    """Return which API keys are configured."""
    return {
        'abuseipdb':      bool(_key('ABUSEIPDB_KEY')),
        'virustotal':     bool(_key('VIRUSTOTAL_KEY')),
        'malwarebazaar':  True,  # No key required
        'shodan':         bool(_key('SHODAN_KEY')),
    }
