import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

import cleanup
from app import create_app, MailBackend, PanelError


class PanelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app({'TESTING': True, 'SECRET_KEY': 'x' * 40,
                               'PASSWORD_HASH': generate_password_hash('test-password-123'),
                               'MODE': 'demo', 'DOMAINS': ['example.com'],
                               'DB_PATH': self.temp.name + '/demo.db'})
        self.client = self.app.test_client()
        self.csrf = self.client.get('/api/session').json['csrf']

    def tearDown(self):
        self.temp.cleanup()

    def post(self, path, data):
        return self.client.post('/api/' + path, json=data, headers={'X-CSRF-Token': self.csrf})

    def login(self):
        result = self.post('login', {'password': 'test-password-123'})
        self.assertEqual(result.status_code, 200)
        self.csrf = result.json['csrf']

    def test_auth_and_csrf(self):
        self.assertEqual(self.client.get('/api/status').status_code, 401)
        self.assertEqual(self.client.post('/api/login', json={'password': 'x'}).status_code, 403)
        self.login()
        self.assertEqual(self.client.get('/api/status').json['mode'], 'demo')
        self.assertEqual(self.client.post('/api/emails/create', json={}).status_code, 403)

    def test_full_email_lifecycle_and_confirmation(self):
        self.login()
        data = {'domain': 'example.com', 'user': 'support', 'password': 'long-password-123'}
        self.assertEqual(self.post('emails/create', data).status_code, 200)
        self.assertEqual(self.client.get('/api/emails?domain=example.com').json['emails'], ['support@example.com'])
        self.assertEqual(self.post('emails/create', data).status_code, 400)
        self.assertEqual(self.post('emails/delete', {'email': 'support@example.com'}).status_code, 400)
        self.assertEqual(self.post('emails/delete', {'email': 'support@example.com', 'confirmation': 'support@example.com'}).status_code, 200)
        self.assertEqual(self.client.get('/api/emails?domain=example.com').json['emails'], [])

    def test_disallowed_domains_and_injection(self):
        self.login()
        for user, domain in [('x; touch /tmp/no', 'example.com'), ('support', 'other.com')]:
            self.assertEqual(self.post('emails/create', {'user': user, 'domain': domain, 'password': 'long-password-123'}).status_code, 400)
        self.assertEqual(self.client.get('/api/emails?domain=other.com').status_code, 400)

    def test_demo_cannot_clean_server(self):
        self.login()
        self.assertEqual(self.post('cleanup/preview', {'category': 'system'}).status_code, 400)
        self.assertEqual(self.post('cleanup/execute', {'confirmation': 'حذف'}).status_code, 400)

    def test_retention_requires_login_and_demo_is_explicit(self):
        self.assertEqual(self.client.get('/api/retention').status_code, 401)
        self.login()
        result = self.client.get('/api/retention').json
        self.assertEqual(result['mode'], 'demo')
        self.assertEqual(result['monitoring'], 'not_verified')
        self.assertEqual(result['accounts'], [])

    def test_combined_cleanup_preserves_files_not_in_preview(self):
        self.login()
        self.app.config['MODE'] = 'cyberpanel'
        first = Path(self.temp.name, 'logs')
        second = Path(self.temp.name, 'cache')
        first.mkdir()
        second.mkdir()
        old = first / 'access.log.1'
        cache = second / 'package.deb'
        active = first / 'access.log'
        for path in (old, cache, active):
            path.write_text('content')
            os.utime(path, (time.time() - 20 * 86400,) * 2)
        policies = {'testlogs': ('Logs', str(first), 'logs'), 'testcache': ('Cache', str(second), 'apt')}
        with patch.dict(cleanup.POLICIES, policies, clear=True):
            plan = self.post('cleanup/preview', {'category': 'all'}).json
            self.assertEqual(len(plan['files']), 2)
            added = first / 'new.log.1'
            added.write_text('keep')
            os.utime(added, (time.time() - 20 * 86400,) * 2)
            result = self.post('cleanup/execute', {'token': plan['token'], 'confirmation': 'حذف'})
            self.assertEqual(result.json['deleted'], 2)
            self.assertTrue(active.exists())
            self.assertTrue(added.exists())
            self.assertFalse(old.exists())
            self.assertFalse(cache.exists())

    def test_rate_limit(self):
        for _ in range(5):
            self.assertEqual(self.post('login', {'password': 'wrong'}).status_code, 401)
        self.assertEqual(self.post('login', {'password': 'test-password-123'}).status_code, 429)

    def test_logout_and_security_headers(self):
        self.login()
        self.assertEqual(self.post('logout', {}).status_code, 200)
        self.assertEqual(self.client.get('/api/status').status_code, 401)
        response = self.client.get('/')
        self.assertIn('frame-ancestors', response.headers['Content-Security-Policy'])
        self.assertIn('لوحة إدارة السيرفر', response.text)

    def test_real_adapter_rejects_false_success(self):
        backend = MailBackend('cyberpanel', '')
        import subprocess
        response = subprocess.CompletedProcess([], 0, 'MAIL_PANEL_RESULT={"ok": false}\n', '')
        with patch('app.subprocess.run', return_value=response):
            with self.assertRaises(PanelError):
                backend.call('create', domain='example.com', user='a', password='secret')

    def test_password_sent_on_stdin_only(self):
        backend = MailBackend('cyberpanel', '')
        import subprocess
        response = subprocess.CompletedProcess([], 0, 'MAIL_PANEL_RESULT={"ok": true}\n', '')
        with patch('app.subprocess.run', return_value=response) as run:
            backend.call('create', domain='example.com', user='a', password='private-password')
            self.assertNotIn('private-password', str(run.call_args.args))
            self.assertIn('private-password', run.call_args.kwargs['input'])

    def test_cleanup_api_confirmation_replay_and_expiry(self):
        self.login()
        self.app.config['MODE'] = 'cyberpanel'
        path = Path(self.temp.name, 'old.log.1')
        path.write_text('old')
        os.utime(path, (time.time() - 20 * 86400,) * 2)
        with patch.dict(cleanup.POLICIES, {'test': ('Test', self.temp.name, 'logs')}):
            plan = self.post('cleanup/preview', {'category': 'test'}).json
            self.assertEqual(len(plan['files']), 1)
            self.assertEqual(self.post('cleanup/execute', {'token': plan['token'], 'confirmation': 'no'}).status_code, 400)
            self.assertTrue(path.exists())
            plan = self.post('cleanup/preview', {'category': 'test'}).json
            response = self.post('cleanup/execute', {'token': plan['token'], 'confirmation': 'حذف'})
            self.assertEqual(response.json['deleted'], 1)
            self.assertFalse(path.exists())
            self.assertEqual(self.post('cleanup/execute', {'token': plan['token'], 'confirmation': 'حذف'}).status_code, 400)
            plan = self.post('cleanup/preview', {'category': 'test'}).json
            with patch('app.time.monotonic', return_value=time.monotonic() + 301):
                self.assertEqual(self.post('cleanup/execute', {'token': plan['token'], 'confirmation': 'حذف'}).status_code, 400)


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.policy = patch.dict(cleanup.POLICIES, {'test': ('Test', str(self.root), 'logs')})
        self.policy.start()

    def tearDown(self):
        self.policy.stop()
        self.temp.cleanup()

    def file(self, name, old=True):
        path = self.root / name
        path.write_text('important content')
        if old:
            os.utime(path, (time.time() - 20 * 86400,) * 2)
        return path

    def test_preserves_active_recent_symlinks_and_directories(self):
        old = self.file('access.log.1')
        self.file('access.log')
        self.file('recent.log.gz', old=False)
        self.file('database.sql')
        (self.root / 'linked.log.gz').symlink_to(old)
        (self.root / 'directory.gz').mkdir()
        plan = cleanup.preview('test')
        self.assertEqual([f['name'] for f in plan['files']], ['access.log.1'])
        self.assertEqual(cleanup.execute('test', plan['files'])['deleted'], 1)
        self.assertTrue((self.root / 'access.log').exists())

    def test_changed_files_are_skipped(self):
        path = self.file('old.log.gz')
        plan = cleanup.preview('test')
        path.write_text('new active contents')
        result = cleanup.execute('test', plan['files'])
        self.assertEqual(result['deleted'], 0)
        self.assertEqual(result['skipped'], 1)
        self.assertTrue(path.exists())

    def test_replaced_symlink_is_skipped(self):
        path = self.file('old.log.gz')
        target = self.file('private.txt')
        plan = cleanup.preview('test')
        path.unlink()
        path.symlink_to(target)
        self.assertEqual(cleanup.execute('test', plan['files'])['deleted'], 0)
        self.assertTrue(target.exists())

    def test_symlink_directory_rejected(self):
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with patch.dict(cleanup.POLICIES, {'linked': ('Test', str(link), 'logs')}):
            with self.assertRaises(ValueError):
                cleanup.preview('linked')


if __name__ == '__main__':
    unittest.main()
