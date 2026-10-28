import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from app import create_app
from bulk_worker import process_one
import management


class BulkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app({'TESTING': True, 'SECRET_KEY': 'x' * 40,
                              'PASSWORD_HASH': generate_password_hash('test-password-123'),
                              'MODE': 'demo', 'DOMAINS': ['example.com'],
                              'DB_PATH': self.temp.name + '/demo.db'})
        self.client = self.app.test_client()
        self.csrf = self.client.get('/api/session').json['csrf']
        response = self.post('login', {'password': 'test-password-123'})
        self.csrf = response.json['csrf']
        self.store = self.app.extensions['management_store']
        self.backend = self.app.extensions['mail_backend']

    def tearDown(self):
        self.temp.cleanup()

    def post(self, path, data):
        return self.client.post('/api/' + path, json=data, headers={'X-CSRF-Token': self.csrf})

    def create_batch(self, count=3, public=False, key='unique-request-123456'):
        result = self.post('bulk/create', {'domain': 'example.com', 'count': count,
                         'prefix': 'mail', 'request_id': key, 'public': public,
                         'confirmation': 'صناديق عامة' if public else ''})
        self.assertEqual(result.status_code, 202, result.json)
        return result.json['job']

    def drain(self):
        for _ in range(20):
            if not process_one(self.store, self.backend, 'demo'):
                break

    def test_batch_create_passwords_encrypted_and_idempotent(self):
        job = self.create_batch()
        self.assertEqual(self.create_batch(), job)
        self.drain()
        rows = self.client.get('/api/accounts?domain=example.com').json['accounts']
        self.assertEqual(len(rows), 3)
        self.assertEqual(len({r['password'] for r in rows}), 3)
        for row in rows:
            self.assertEqual(len(row['password']), 8)
            self.assertRegex(row['password'], r'^[a-z0-9]{8}$')
            self.assertRegex(row['email'].split('@')[0], r'^[a-z0-9]{8}$')
            self.assertNotIn(row['password'].encode(), self.store.path.read_bytes())
            self.assertFalse(row['public'])
        self.assertEqual(os.stat(self.store.path).st_mode & 0o777, 0o600)
        self.assertEqual(self.store.jobs()[0]['counts'], {'done': 3})

    def test_accept_2000_without_running_mass_creation(self):
        self.create_batch(2000)
        self.assertEqual(self.store.jobs()[0]['counts'], {'queued': 2000})
        self.assertEqual(self.backend.call('inventory'), [])

    def test_batch_validation_and_public_optin(self):
        for count in (0, 2001, True, '2000'):
            self.assertEqual(self.post('bulk/create', {'domain': 'example.com', 'count': count}).status_code, 400)
        self.assertEqual(self.post('bulk/create', {'domain': 'other.org', 'count': 2}).status_code, 400)
        self.assertEqual(self.post('bulk/create', {'domain': 'example.com', 'count': 2,
                         'public': True, 'request_id': 'unique-request-123456'}).status_code, 400)

    def test_delete_by_count_freezes_targets_and_forgets_passwords(self):
        self.create_batch()
        self.drain()
        preview = self.post('bulk/delete/preview', {'domain': 'example.com', 'count': 2}).json
        self.assertEqual(len(preview['emails']), 2)
        result = self.post('bulk/delete/execute', {'token': preview['token'], 'confirmation': preview['confirmation']})
        self.assertEqual(result.status_code, 202)
        self.assertEqual(self.post('bulk/delete/execute', {'token': preview['token'], 'confirmation': preview['confirmation']}).status_code, 400)
        self.drain()
        self.assertEqual(len(self.backend.call('inventory')), 1)
        for email in preview['emails']:
            self.assertIsNone(self.store.account(email))

    def test_delete_explicit_selection_and_confirmation(self):
        self.create_batch()
        self.drain()
        chosen = self.backend.call('inventory')[1]
        preview = self.post('bulk/delete/preview', {'domain': 'example.com', 'emails': [chosen]}).json
        self.assertEqual(preview['emails'], [chosen])
        self.assertEqual(self.post('bulk/delete/execute', {'token': preview['token'], 'confirmation': 'wrong'}).status_code, 400)
        self.assertEqual(len(self.backend.call('inventory')), 3)

    def test_private_unknown_and_deleted_boxes_are_not_public(self):
        self.create_batch()
        self.drain()
        email = self.backend.call('inventory')[0]
        visitor = self.app.test_client()
        self.assertEqual(visitor.post('/public-api/messages', json={'email': email}).status_code, 404)
        self.assertEqual(visitor.get('/api/accounts?domain=example.com').status_code, 401)
        self.assertEqual(self.post('accounts/public', {'email': email, 'enabled': True}).status_code, 400)
        self.assertEqual(self.post('accounts/public', {'email': email, 'enabled': True, 'confirmation': email}).status_code, 200)
        self.assertEqual(visitor.post('/public-api/messages', json={'email': email}).json, {'messages': [], 'demo': True})
        self.assertEqual(self.post('accounts/public', {'email': email, 'enabled': False}).status_code, 200)
        self.assertEqual(visitor.post('/public-api/messages', json={'email': email}).status_code, 404)

    def test_public_api_never_returns_credentials_and_verifies_account_exists(self):
        self.create_batch(1, public=True)
        self.drain()
        email = self.backend.call('inventory')[0]
        self.app.config['MODE'] = 'cyberpanel'
        visitor = self.app.test_client()
        fake = [{'id': '1', 'subject': '<script>bad()</script>', 'sender': 'a@b.org', 'date': '', 'text': 'hello', 'limited': False}]
        with patch('inbox_reader.read_messages', return_value=fake):
            response = visitor.post('/public-api/messages', json={'email': email})
            self.assertEqual(response.json['messages'], fake)
            self.assertNotIn('password', response.json)
        self.backend.call('delete', email=email)
        self.assertEqual(visitor.post('/public-api/messages', json={'email': email}).status_code, 404)
        self.assertIsNone(self.store.account(email))

    def test_cancel_pending_job_does_not_create_accounts(self):
        job = self.create_batch()
        self.post('jobs/cancel', {'job': job})
        self.drain()
        self.assertEqual(self.backend.call('inventory'), [])
        self.assertEqual(self.store.jobs()[0]['status'], 'cancelled')

    def test_running_tasks_are_not_replayed_after_restart(self):
        self.create_batch()
        self.store.claim()
        self.store.recover()
        self.drain()
        self.assertEqual(self.backend.call('inventory'), [])
        self.assertEqual(self.store.jobs()[0]['status'], 'paused')
        self.assertEqual(self.store.jobs()[0]['counts']['uncertain'], 1)

    def test_failure_pauses_job_without_leaking_password(self):
        self.create_batch()
        with patch.object(self.backend, 'call', side_effect=RuntimeError('private-secret')):
            process_one(self.store, self.backend, 'demo')
        job = self.store.jobs()[0]
        self.assertEqual(job['status'], 'paused')
        self.assertNotIn('private-secret', json.dumps(job))
        self.assertEqual(job['counts']['queued'], 2)

    def test_public_rate_limit(self):
        visitor = self.app.test_client()
        for _ in range(30):
            visitor.post('/public-api/messages', json={'email': 'missing@example.com'})
        self.assertEqual(visitor.post('/public-api/messages', json={'email': 'missing@example.com'}).status_code, 429)

    def test_creation_order_selection_and_exact_text_export(self):
        for user in ('zzzzzzz1', 'aaaaaaa1'):
            self.assertEqual(self.post('emails/create', {'domain': 'example.com', 'user': user, 'password': 'Abcd1234'}).status_code, 200)
        rows = self.client.get('/api/accounts?domain=example.com').json['accounts']
        self.assertEqual([r['email'] for r in rows], ['zzzzzzz1@example.com', 'aaaaaaa1@example.com'])
        preview = self.post('bulk/delete/preview', {'domain': 'example.com', 'count': 1}).json
        self.assertEqual(preview['emails'], ['zzzzzzz1@example.com'])
        export = self.post('accounts/export', {'domain': 'example.com', 'emails': [r['email'] for r in reversed(rows)]})
        self.assertEqual(export.status_code, 200)
        self.assertEqual(export.text.splitlines(), [f'{r["email"]} : Abcd1234 : https://mail.jxil.org:8090/snappymail/' for r in rows])
        self.assertEqual(export.headers['Cache-Control'], 'no-store')
        self.assertIn('attachment', export.headers['Content-Disposition'])

    def test_export_protected_and_unknown_password_not_fabricated(self):
        self.backend.call('create', domain='example.com', user='legacy01', password='Abcd1234')
        self.assertEqual(self.post('accounts/export', {'domain': 'example.com', 'emails': ['legacy01@example.com']}).status_code, 400)
        self.assertEqual(self.app.test_client().post('/api/accounts/export', json={}).status_code, 401)
        self.assertEqual(self.client.post('/api/accounts/export', json={}).status_code, 403)

    def test_opened_page_filters_only_observed_logins(self):
        self.create_batch(2)
        self.drain()
        emails = self.backend.call('inventory')
        self.app.config['MODE'] = 'cyberpanel'
        with patch('retention.read_login', side_effect=lambda address: {'first_login': 1700000000} if address == emails[0] else None):
            rows = self.client.get('/api/accounts?domain=example.com&opened=1').json['accounts']
            unopened = self.client.get('/api/accounts?domain=example.com&unopened=1').json['accounts']
        self.assertEqual([r['email'] for r in rows], [emails[0]])
        self.assertEqual([r['email'] for r in unopened], [emails[1]])
        self.assertEqual(rows[0]['first_login'], 1700000000)
        self.assertEqual(self.client.get('/opened').status_code, 200)

    def test_single_new_account_requires_eight_alphanumeric_characters(self):
        for user, password in [('short1', 'Abcd1234'), ('abcdefgh', 'Abcd1234'), ('abcd1234', 'too-long-123'), ('abcd1234', 'abcdefgh')]:
            self.assertEqual(self.post('emails/create', {'domain': 'example.com', 'user': user, 'password': password}).status_code, 400)

    def test_expiry_command_cannot_delete_automatically(self):
        import subprocess
        import sys
        result = subprocess.run([sys.executable, str(Path(__file__).parents[1] / 'expiry_worker.py'), '--apply'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('disabled', result.stdout)

    def test_legacy_vault_migration_preserves_credentials(self):
        import sqlite3
        path = Path(self.temp.name) / 'old.sqlite'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE accounts(email TEXT PRIMARY KEY,password BLOB NOT NULL,public INTEGER NOT NULL,status TEXT NOT NULL)')
            db.execute('INSERT INTO accounts VALUES (?,?,?,?)', ('old@example.com', self.store.cipher.encrypt(b'old-password'), 0, 'active'))
        migrated = management.Store(path, 'x' * 40)
        self.assertEqual(migrated.account('old@example.com')['password'], 'old-password')
        self.assertEqual(migrated.account('old@example.com')['order_source'], 'legacy')


if __name__ == '__main__':
    unittest.main()
