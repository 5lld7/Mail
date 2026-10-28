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
            self.assertGreaterEqual(len(row['password']), 24)
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


if __name__ == '__main__':
    unittest.main()
