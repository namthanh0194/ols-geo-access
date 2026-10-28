import ipaddress
import json
import subprocess
from datetime import datetime
from urllib.parse import urlencode
from urllib.request import urlopen

from lib.domain_inventory import _validate_domain

INTERVAL_SECONDS = 23 * 60 * 60
MAX_GAP_SECONDS = 36 * 60 * 60


def resolve_addresses(domain):
    _validate_domain(domain)
    addresses = set()
    for record_type, version in ((1, 4), (28, 6)):
        query = urlencode({'name': domain, 'type': record_type})
        with urlopen('https://dns.google/resolve?' + query, timeout=5) as response:
            body = response.read(262145)
        if len(body) > 262144:
            raise ValueError('Phản hồi DNS quá lớn')
        payload = json.loads(body)
        if not isinstance(payload, dict) or payload.get('Status') != 0 or payload.get('TC'):
            raise ValueError('DNS không trả về kết quả đầy đủ (NXDOMAIN/lỗi DNS)')
        answers = payload.get('Answer', [])
        if not isinstance(answers, list):
            raise ValueError('Phản hồi DNS không hợp lệ')
        for answer in answers:
            if not isinstance(answer, dict):
                raise ValueError('Bản ghi DNS không hợp lệ')
            if answer.get('type') == record_type:
                address = ipaddress.ip_address(answer.get('data', ''))
                if address.version != version:
                    raise ValueError('Sai loại địa chỉ DNS')
                addresses.add(str(address))
    return sorted(addresses)


def local_origin_addresses():
    result = subprocess.run(
        ['ip', '-j', 'address', 'show', 'scope', 'global'],
        check=True, capture_output=True, text=True, timeout=5,
    )
    addresses = set()
    for interface in json.loads(result.stdout):
        for entry in interface.get('addr_info', []):
            address = ipaddress.ip_address(entry['local'])
            if address.is_global:
                addresses.add(str(address))
    return addresses


def classify_addresses(addresses, cloudflare_prefixes, origin_addresses):
    def unknown(reason):
        return {'mode': 'unknown', 'reason': reason}

    if not cloudflare_prefixes:
        return unknown('Chưa có dải IP Cloudflare hợp lệ và còn hạn')
    try:
        networks = [ipaddress.ip_network(prefix) for prefix in cloudflare_prefixes]
        resolved = {ipaddress.ip_address(address) for address in addresses}
        origins = {ipaddress.ip_address(address) for address in origin_addresses}
    except ValueError:
        return unknown('Địa chỉ IP không hợp lệ')
    if not resolved or not all(address.is_global for address in resolved):
        return unknown('DNS chưa có đủ địa chỉ IP công khai hợp lệ')
    if all(any(address in network for network in networks) for address in resolved):
        return {'mode': 'cloudflare', 'reason': 'Toàn bộ bản ghi A/AAAA thuộc Cloudflare'}
    if resolved <= origins:
        return {'mode': 'direct', 'reason': 'Toàn bộ bản ghi A/AAAA trỏ IP công khai trên máy chủ'}
    return unknown('DNS hỗn hợp, CDN khác hoặc IP origin chưa xác minh được')


def observe(previous, result, now):
    previous = previous or {}
    mode = result['mode']
    observation = {
        'mode': mode, 'reason': result['reason'], 'checked_at': now.isoformat(),
        'status': 'unknown' if mode == 'unknown' else 'pending',
        'candidate_since': now.isoformat(),
    }
    if mode == 'unknown' or previous.get('mode') != mode:
        return observation
    try:
        checked_at = datetime.fromisoformat(previous['checked_at'])
        candidate_since = datetime.fromisoformat(previous['candidate_since'])
        gap = (now - checked_at).total_seconds()
        age = (now - candidate_since).total_seconds()
        if 0 <= gap <= MAX_GAP_SECONDS and age >= 0:
            observation['candidate_since'] = candidate_since.isoformat()
            if age >= INTERVAL_SECONDS:
                observation['status'] = 'confirmed'
    except (KeyError, TypeError, ValueError):
        pass
    return observation
