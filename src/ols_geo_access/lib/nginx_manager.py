import hashlib
import http.client
import ipaddress
import json
import os
import shutil
import socket
import time
from pathlib import Path

from lib import nginx_rollback as engine
from lib.cloudflare_ranges import snapshot_freshness, validate_cloudflare_snapshot, prepare_cloudflare_snapshot
from lib.config_store import load_json, validate_domains
from lib.config_validator import validate_geoip_database
from lib.domain_inventory import _nginx_parse, collect_domains_nginx
from lib.transaction import process_lock
from lib.feed_updater import PROVIDER_SOURCES, enabled_snapshot_names, enabled_feeds, validate_snapshot_transition, validate_feed_network
from lib.nginx_config_generator import generate_nginx_http_conf, generate_nginx_server_snippet
from lib.nginx_prerequisites import pending_operations, prerequisite_lock


class NginxManager:
    def __init__(self, app):
        self.app = app
        self.paths = app._paths
        self.state = self.paths.data / 'nginx-release-state'
        self.releases = self.paths.root / 'generated/nginx-releases'
        self.http = app._vhost_root / '00-ols-geo-access-http.conf'
        self.socket = self.paths.data / 'nginx-runtime/probe.sock'

    def requirements(self):
        missing = []
        try:
            if pending_operations(self.paths.root):
                missing.append('Thiết lập module/database Nginx chưa hoàn tất; cần kiểm tra bản sao lưu')
        except (OSError, ValueError) as error:
            missing.append('Không đọc được trạng thái thiết lập Nginx: ' + str(error))
        if not self.app._adapter or not self.app._adapter.check_realip_support():
            missing.append('Thiếu module RealIP')
        if not self.app._adapter or not self.app._adapter.check_geoip2_support():
            missing.append('Thiếu module GeoIP2 đang được Nginx nạp')
        try:
            validate_geoip_database(self.app._geoip_database)
        except (OSError, ValueError) as error:
            missing.append('MMDB chưa sẵn sàng: ' + str(error))
        try:
            config = engine._safe_path(self.app._server_config_path)
            blocks = [children for fields, children in _nginx_parse(config.read_text()) if fields == ('http',) and children is not None]
            expected = ('include', str(self.app._vhost_root / '*.conf'))
            if len(blocks) != 1 or sum(fields == expected and nested is None for fields, nested in blocks[0]) != 1:
                missing.append('Thiếu include HTTP wildcard duy nhất của aaPanel')
            if len(os.fsencode(self.socket)) > 100:
                missing.append('Đường dẫn Unix socket quá dài')
        except (OSError, ValueError) as error:
            missing.append('Không xác minh được HTTP include: ' + str(error))
        try:
            unavailable = self.missing_snapshots()
            if unavailable:
                missing.append('Chờ khởi tạo feed crawler: ' + ', '.join(unavailable))
        except (OSError, ValueError) as error:
            missing.append('Không kiểm tra được feed crawler: ' + str(error))
        return missing

    def missing_snapshots(self):
        missing = []
        for name in enabled_feeds(load_json(self.paths, 'providers')):
            try:
                candidate = engine._load_json(self.app._snapshots_root / (name + '.json'))
                canonical = ('\n'.join(candidate['prefixes']) + '\n').encode()
                if candidate['provider'] != name or candidate['source'] != PROVIDER_SOURCES[name] or engine.sha256_bytes(canonical) != candidate['checksum']:
                    raise ValueError('Invalid snapshot identity/checksum')
                if not candidate['prefixes']:
                    raise ValueError('Empty crawler snapshot')
                for prefix in candidate['prefixes']:
                    validate_feed_network(name, ipaddress.ip_network(prefix, strict=True))
            except (OSError, ValueError, KeyError, TypeError):
                missing.append(name)
        return missing

    def options(self):
        return {'database_path': self.app._database_path, 'probe': self.probe}

    def sentinel(self, release_id):
        engine._identifier(release_id)
        path = engine._safe_path(self.socket)
        if len(os.fsencode(path)) > 100 or any(char in str(path) for char in '";{}$\\'):
            raise ValueError('Unsafe Nginx probe socket')
        return '\nserver {\n    listen unix:' + str(path) + ';\n    server_name localhost;\n    access_log off;\n    location / { return 200 "' + release_id + '"; }\n}\n'

    def probe(self, current):
        if current is None or (current.get('status') == 'deactivated' and not current['http_conf']['exists']):
            self.app._adapter.get_runtime_identity()
            return self.app._adapter.test_config().valid
        expected = 'deactivated' if current.get('status') == 'deactivated' else current['release_id']
        for attempt in range(40):
            connection = None
            try:
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(0.25)
                connection.connect(str(self.socket))
                connection.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
                response = http.client.HTTPResponse(connection)
                response.begin()
                if response.status == 200 and response.read(256).decode() == expected:
                    return True
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                if connection is not None:
                    connection.close()
            time.sleep(0.05)
        return False

    def _context(self):
        return engine._Context(self.app._vhost_root, self.http, self.state, self.app._adapter, **self.options())

    def status(self):
        pending_setup = pending_operations(self.paths.root)
        if pending_setup:
            return {'status': 'recovery_required', 'pending': pending_setup, 'current': None,
                    'blocking': True, 'safe_action': 'manual',
                    'reason': 'Giao dịch thiết lập Nginx chưa hoàn tất; cần kiểm tra backup trước khi tiếp tục.'}
        state = engine._safe_path(self.state)
        if not state.exists() or not any(path.name not in {'deployment.lock', '.operation.lock'} for path in state.iterdir()):
            if engine._safe_path(self.http).exists() or any(self.app._vhost_root.glob('extension/*/00-ols-geo-access.conf')):
                raise ValueError('Unowned Nginx managed artifacts require manual review')
            return {'status': 'clean', 'pending': [], 'current': None, 'blocking': False, 'safe_action': 'none'}
        context = self._context()
        with context.lock():
            current_path = self.state / 'current.json'
            current = engine._load_json(current_path) if current_path.exists() else None
            context.validate_current(current)
            pending = []
            directory = self.state / 'transactions'
            if directory.exists():
                for path in sorted(directory.iterdir()):
                    journal = engine._journal(context, path.name)
                    if journal['status'] not in engine.TERMINAL_STATUSES:
                        pending.append(path.name)
            if current and not pending:
                owned = {'http': current['http_conf'], **current['managed_snippets']}
                for key, snapshot in owned.items():
                    if engine._read_file(context.target(key))[1] != snapshot:
                        raise engine.NginxRecoveryRequired('Managed Nginx file changed: ' + key)
            return {'status': 'recovery_required' if pending else 'clean', 'pending': pending, 'current': current,
                    'blocking': bool(pending), 'safe_action': 'restore' if len(pending) == 1 else 'manual',
                    'operation_id': pending[0] if len(pending) == 1 else None,
                    'reason': 'Giao dịch Nginx chưa hoàn tất; cần khôi phục trước khi lưu tiếp.' if pending else ''}

    def _settings(self, changes, overrides):
        payloads, expected = {}, {}
        for name in ('domains', 'config', 'providers', 'woo_exceptions', 'ip_allowlist', 'cloudflare_prefixes'):
            path = self.paths.data_file(name)
            content, snapshot = engine._read_file(path)
            expected[path.name] = snapshot
            if content is not None:
                payloads[path.name] = content
        for name, document in changes.items():
            path = self.paths.data_file(name)
            expected.setdefault(path.name, engine._read_file(path)[1])
            payloads[path.name] = self.app._json_bytes(name, document)
        snapshots = overrides.get('snapshots')
        if snapshots is None:
            snapshots = {path.stem: json.loads(engine._read_file(path)[0]) for path in self.app._snapshots_root.glob('*.json')}
        providers = json.loads(payloads['providers.json'])
        enabled = set(enabled_snapshot_names(providers))
        missing_snapshots = sorted(enabled - set(snapshots)) if any(item.get('enabled') and item.get('group') != 'NONE' for item in json.loads(payloads['domains.json'])['domains'].values()) else []
        if missing_snapshots:
            raise ValueError('Thiếu dữ liệu crawler đã bật: ' + ', '.join(missing_snapshots) + '; hãy cập nhật feed trước khi bật bảo vệ')
        filtered = {}
        for name, snapshot in snapshots.items():
            if name not in enabled:
                continue
            if snapshot.get('provider') != name:
                raise ValueError('Crawler snapshot identity mismatch')
            validate_snapshot_transition(None, snapshot)
            canonical = ('\n'.join(snapshot['prefixes']) + '\n').encode()
            if hashlib.sha256(canonical).hexdigest() != snapshot['checksum']:
                raise ValueError('Crawler snapshot checksum mismatch')
            relative = engine._setting_name('snapshots/' + name + '.json')
            expected[relative] = engine._read_file(self.paths.data / relative)[1]
            payloads[relative] = self.app._json_bytes('snapshot', snapshot)
            filtered[name] = snapshot
        return payloads, expected, filtered

    def build(self, assignments, changes=None, overrides=None):
        validate_domains({'schema_version': 1, 'domains': assignments})
        overrides = overrides or {}
        settings, expected, snapshots = self._settings(changes or {}, overrides)
        settings['domains.json'] = self.app._json_bytes('domains', {'schema_version': 1, 'domains': assignments})
        active = {domain: item for domain, item in assignments.items() if item['enabled'] and item['group'] != 'NONE'}
        records = {record.domain: record for record in collect_domains_nginx(self.app._database_path, self.app._vhost_root, config_prefix=self.app._server_config_path.parent)}
        for domain in active:
            if domain not in records or not records[domain].supported_for_protection:
                raise ValueError(domain + ': ' + (records[domain].unsupported_reason if domain in records else 'Website không còn trong aaPanel'))
        prefixes = ()
        if any(item['traffic_mode'] == 'cloudflare' for item in active.values()):
            snapshot = validate_cloudflare_snapshot(json.loads(settings['cloudflare_prefixes.json']))
            if snapshot_freshness(snapshot, now=self.app._clock())['blocking']:
                try:
                    candidate = prepare_cloudflare_snapshot(self.app._cloudflare_downloader(), previous=snapshot,
                                                            checked_at=self.app._clock().isoformat())
                    settings['cloudflare_prefixes.json'] = self.app._json_bytes('cloudflare_prefixes', candidate)
                    snapshot = candidate
                except Exception:
                    pass
            if snapshot_freshness(snapshot, now=self.app._clock())['blocking']:
                raise ValueError('Cloudflare IP snapshot is stale; update ranges before applying')
            prefixes = snapshot['prefixes']
        if active:
            http = generate_nginx_http_conf(self.app._geoip_database, prefixes, assignments=assignments, snapshots=snapshots,
                exceptions=overrides.get('exceptions', json.loads(settings['woo_exceptions.json'])['exceptions']),
                allowlist=overrides.get('allowlist', json.loads(settings['ip_allowlist.json'])['entries']))
        else:
            http = '# No protected Nginx websites\n'
        snippets = {domain: generate_nginx_server_snippet(domain, item, cloudflare_prefixes=prefixes) for domain, item in active.items()}
        digest = hashlib.sha256(http.encode() + engine._json_bytes(snippets) + engine._json_bytes({name: hashlib.sha256(content).hexdigest() for name, content in settings.items()})).hexdigest()
        release_id = 'nginx-' + digest[:32]
        self.releases.mkdir(parents=True, exist_ok=True, mode=0o700)
        engine._safe_path(self.releases)
        root = self.releases / release_id
        if not root.exists():
            engine.build_nginx_release(release_id, self.releases, http + self.sentinel(release_id), snippets, settings=settings)
        return release_id, expected

    def deploy(self, *, state_changes, assignments, build_overrides=None, action_name='', expected_domains=None):
        with process_lock(self.state / '.operation.lock'):
            if expected_domains is not None and load_json(self.paths, 'domains') != expected_domains:
                raise ValueError('Cấu hình website đã thay đổi; thử lại')
            release_id, expected = self.build(assignments, state_changes, build_overrides)
            engine._safe_path(self.socket.parent)
            self.socket.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.socket.parent, 0o700)
            result = engine.apply_nginx_release(release_id, self.releases, self.app._vhost_root, self.http, self.state,
                        self.app._adapter, expected_settings=expected, **self.options())
            self.app._audit.record_action(action_name or 'nginx.apply', {'result': result['status'], 'release_id': release_id})
            self.prune()
            return result

    def rollback(self):
        current = self.status()['current']
        if not current:
            raise ValueError('No current Nginx release to roll back')
        release_id = current['release_id'] if current['status'] == 'deactivated' else current.get('parent_release')
        engine._identifier(release_id)
        self.validate_release_policy(release_id)
        return engine.rollback_nginx_release(self.releases, self.app._vhost_root, self.http, self.state, self.app._adapter, **self.options())

    def apply_staged(self, release_id):
        engine._identifier(release_id)
        self.validate_release_policy(release_id)
        self.socket.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        return engine.apply_nginx_release(release_id, self.releases, self.app._vhost_root, self.http, self.state,
                    self.app._adapter, **self.options())

    def validate_release_policy(self, release_id):
        settings = engine._candidate_settings(self._context(), release_id)
        required = {'domains.json', 'config.json', 'providers.json', 'woo_exceptions.json', 'ip_allowlist.json'}
        if not required <= settings.keys():
            raise ValueError('Nginx release has no complete policy snapshot')
        documents = {name[:-5]: json.loads(content) for name, content in settings.items() if '/' not in name}
        for name, document in documents.items():
            self.app._json_bytes(name, document)
        assignments = documents['domains']['domains']
        if any(value.get('enabled') and value.get('group') != 'NONE' and value.get('traffic_mode') == 'cloudflare' for value in assignments.values()):
            snapshot = validate_cloudflare_snapshot(documents.get('cloudflare_prefixes', {}))
            if snapshot_freshness(snapshot, now=self.app._clock())['blocking']:
                raise ValueError('Snapshot Cloudflare trong bản cấu hình đã quá hạn; tạo bản mới trước khi áp dụng')

    def scheduled(self, candidates, allowlist_candidate=None):
        try:
            if not isinstance(candidates, dict):
                raise ValueError('Invalid snapshot candidates')
            enabled = set(enabled_feeds(load_json(self.paths, 'providers')))
            snapshots = {path.stem: json.loads(engine._read_file(path)[0]) for path in self.app._snapshots_root.glob('*.json')}
            changed = []
            for name, candidate in candidates.items():
                if name not in enabled or candidate.get('provider') != name:
                    raise ValueError('Provider is not enabled')
                previous = snapshots.get(name)
                validate_snapshot_transition(previous, candidate)
                if previous is None or previous['checksum'] != candidate['checksum']:
                    changed.append(name)
                    snapshots[name] = candidate
            changes = {}
            service_changed = False
            if allowlist_candidate is not None:
                allowlist, metadata, service_changed = allowlist_candidate
                if service_changed:
                    changes['ip_allowlist'] = allowlist
                    state = load_json(self.paths, 'state')
                    state['service_sources'] = {**state.get('service_sources', {}), **metadata}
                    changes['state'] = state
            if not changed and not service_changed:
                return {'status': True, 'updated': [], 'service_updated': False, 'deployment': None}
            assignments = load_json(self.paths, 'domains')['domains']
            deployment = self.deploy(state_changes=changes, assignments=assignments,
                build_overrides={'snapshots': snapshots}, action_name='nginx.feeds.update')
            return {'status': True, 'updated': changed, 'service_updated': service_changed, 'deployment': deployment}
        except (OSError, ValueError, RuntimeError) as error:
            return {'status': False, 'code': 'deployment_failed', 'msg': str(error), 'updated': [],
                    'service_updated': False, 'deployment': None, 'recovery_required': isinstance(error, engine.NginxRecoveryRequired)}

    def bootstrap_snapshots(self, candidates):
        with prerequisite_lock(self.paths.root):
            if (self.state / 'current.json').exists():
                current = engine._load_json(self.state / 'current.json')
                if current['status'] != 'deactivated':
                    raise ValueError('Snapshot-only setup is forbidden while Nginx protection is active')
            enabled = set(enabled_feeds(load_json(self.paths, 'providers')))
            changed = []
            for name, candidate in candidates.items():
                if (name not in enabled or candidate.get('provider') != name
                        or candidate.get('source') != PROVIDER_SOURCES.get(name)):
                    raise ValueError('Invalid Nginx setup snapshot identity')
                content = engine._json_bytes(candidate)
                canonical = ('\n'.join(candidate['prefixes']) + '\n').encode()
                if hashlib.sha256(canonical).hexdigest() != candidate.get('checksum'):
                    raise ValueError('Nginx setup snapshot checksum mismatch')
                if not candidate['prefixes']:
                    raise ValueError('Empty Nginx setup snapshot')
                for prefix in candidate['prefixes']:
                    validate_feed_network(name, ipaddress.ip_network(prefix, strict=True))
                target = self.app._snapshots_root / (name + '.json')
                previous, before = engine._read_file(target)
                validate_snapshot_transition(json.loads(previous) if previous is not None else None, candidate)
                after = engine._snapshot(content, before if before['exists'] else {'mode': 0o600, 'uid': os.geteuid(), 'gid': os.getegid()})
                if before != after:
                    engine._write_file(target, content, after, before)
                    changed.append(name)
            return {'status': True, 'updated': changed, 'service_updated': False,
                    'deployment': None, 'rules_activated': False}

    def refresh_cloudflare(self, check_only=False):
        previous = load_json(self.paths, 'cloudflare_prefixes')
        candidate = prepare_cloudflare_snapshot(self.app._cloudflare_downloader(), previous=previous,
                                                checked_at=self.app._clock().isoformat())
        if check_only:
            return {'status': True, 'snapshot': candidate}
        if candidate['checksum'] == previous.get('checksum') and (self.state / 'current.json').is_file():
            context = self._context()
            with context.lock():
                current = engine._load_json(self.state / 'current.json')
                context.validate_current(current)
                content, before = engine._read_file(self.paths.data_file('cloudflare_prefixes'))
                if json.loads(content) != previous:
                    raise ValueError('Cloudflare snapshot changed during refresh')
                bodies = {key: engine._read_file(context.target(key))[0] for key in ['http', *current['managed_snippets']]}
                result = engine._execute(context, current['release_id'], bodies, 'metadata',
                    settings={'cloudflare_prefixes.json': self.app._json_bytes('cloudflare_prefixes', candidate)},
                    expected_settings={'cloudflare_prefixes.json': before})
            self.app._reload_cloudflare_state()
            return {'status': True, 'deployment': result, 'unchanged': True, 'fallback_used': False}
        result = self.deploy(state_changes={'cloudflare_prefixes': candidate},
            assignments=load_json(self.paths, 'domains')['domains'], action_name='nginx.cloudflare.update')
        self.app._reload_cloudflare_state()
        return {'status': True, 'deployment': result, 'fallback_used': False}

    def recover(self):
        state = self.status()
        if state['safe_action'] == 'manual':
            raise engine.NginxRecoveryRequired('Nginx prerequisite recovery requires backup inspection')
        if len(state['pending']) > 1:
            raise engine.NginxRecoveryRequired('Multiple pending Nginx transactions require manual review')
        if state['pending']:
            engine.restore_nginx_release_transaction(state['pending'][0], self.state, self.app._vhost_root,
                        self.http, self.app._adapter, **self.options())
        return self.status()

    def deactivate(self):
        state = self.status()
        if state['pending']:
            raise engine.NginxRecoveryRequired('Restore pending Nginx deployment before uninstall')
        if not state['current'] or state['current']['status'] == 'deactivated':
            return {'status': 'unchanged', 'backend': 'nginx'}
        settings = load_json(self.paths, 'domains')
        for assignment in settings['domains'].values():
            assignment['enabled'] = False
        return engine.deactivate_nginx_managed_release(self.app._vhost_root, self.http, self.state, self.app._adapter,
            remove_http=True, settings={'domains.json': self.app._json_bytes('domains', settings)}, **self.options())

    def prune(self):
        context = self._context()
        with context.lock():
            engine._pending(context)
            current = engine._load_json(self.state / 'current.json')
            retained = {current['release_id'], current.get('parent_release')}
            manifests = engine.list_nginx_releases(self.releases)
            retained.update(item['release_id'] for item in manifests[:5])
            transactions = self.state / 'transactions'
            journals = sorted((engine._journal(context, path.name) for path in transactions.iterdir()), key=lambda item: item.get('created_at', ''), reverse=True)
            for journal in journals[:5]:
                for state in (journal.get('previous_current'), journal.get('next_current')):
                    if state:
                        retained.add(state['release_id'])
            for journal in journals[5:]:
                if journal['transaction_id'] != current['transaction_id']:
                    shutil.rmtree(engine._safe_path(transactions / journal['transaction_id']))
            for manifest in manifests:
                if manifest['release_id'] not in retained:
                    shutil.rmtree(engine._safe_path(self.releases / manifest['release_id']))
