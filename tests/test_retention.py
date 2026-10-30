import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import retention
from expiry_worker import run


class Backend:
    def __init__(self, *emails):
        self.emails = set(emails)

    def call(self, action, **kwargs):
        if action == 'inventory':
            return sorted(self.emails)
        if action == 'list':
            return sorted(e for e in self.emails if e.endswith('@' + kwargs['domain']))
        if action == 'delete':
            self.emails.discard(kwargs['email'])
            return {'ok': True}
        raise AssertionError(action)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.mail = self.root / 'vmail'
        self.mail.mkdir()
        self.state = self.root / 'state'
        self.patches = [patch.object(retention, 'MAIL_ROOT', self.mail),
                        patch.object(retention, 'STATE_ROOT', self.state),
                        patch('retention.shutil.which', return_value='/usr/bin/doveadm'),
                        patch('retention.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '', ''))]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def account(self, email='user@example.com', age=None):
        user, domain = retention.parts(email)
        path = self.mail / domain / user
        (path / 'Maildir' / 'cur').mkdir(parents=True)
        (path / 'Maildir' / 'cur' / 'message').write_text('mail content')
        if age is not None:
            with patch('retention.time.time', return_value=time.time() - age):
                retention.record_login(email)
        return path

    def test_first_login_is_persistent_and_never_extended(self):
        self.account()
        retention.record_login('user@example.com')
        first = retention.read_login('user@example.com')
        with patch('retention.time.time', return_value=time.time() + 100):
            retention.record_login('user@example.com')
        self.assertEqual(retention.read_login('user@example.com'), first)

    def test_existing_accounts_without_marker_are_not_deleted(self):
        path = self.account()
        backend = Backend('user@example.com')
        self.assertTrue(run(backend, apply=True))
        self.assertTrue(path.exists())
        self.assertIn('user@example.com', backend.emails)

    def test_not_due_and_dry_run_never_delete(self):
        path = self.account(age=60)
        backend = Backend('user@example.com')
        self.assertTrue(run(backend, apply=True))
        self.assertTrue(path.exists())
        with patch('retention.time.time', return_value=time.time() + 90000):
            self.assertTrue(run(backend, apply=False))
        self.assertTrue(path.exists())
        self.assertIn('user@example.com', backend.emails)

    def test_expiry_includes_all_domains_and_deletes_data(self):
        a = self.account(age=90000)
        b = self.account('old@other.org', age=90000)
        backend = Backend('user@example.com', 'old@other.org')
        self.assertTrue(run(backend, apply=True))
        self.assertFalse(a.exists())
        self.assertFalse(b.exists())
        self.assertEqual(backend.emails, set())
        self.assertEqual(retention.pending_jobs(), [])

    def test_purge_does_not_follow_message_symlinks(self):
        path = self.account(age=90000)
        outside = self.root / 'outside'
        outside.mkdir()
        important = outside / 'keep'
        important.write_text('keep')
        (path / 'linked').symlink_to(outside, target_is_directory=True)
        self.assertTrue(run(Backend('user@example.com'), apply=True))
        self.assertEqual(important.read_text(), 'keep')

    def test_mailbox_symlink_is_rejected(self):
        (self.mail / 'example.com').mkdir()
        (self.mail / 'example.com' / 'user').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            retention.record_login('user@example.com')

    def test_corrupt_and_symlink_markers_fail_closed(self):
        path = self.account()
        (path / retention.MARKER).write_text('[]')
        backend = Backend('user@example.com')
        self.assertFalse(run(backend, apply=True))
        self.assertTrue(path.exists())
        (path / retention.MARKER).unlink()
        target = self.root / 'target'
        target.write_text('{}')
        (path / retention.MARKER).symlink_to(target)
        self.assertFalse(run(backend, apply=True))
        self.assertTrue(target.exists())

    def test_due_marker_token_required(self):
        path = self.account(age=90000)
        with retention.operation_lock():
            with self.assertRaises(ValueError):
                retention.purge_mailbox(Backend('user@example.com'), 'user@example.com', expected_token='wrong')
        self.assertTrue(path.exists())

    def test_session_failure_is_retried_after_database_removal(self):
        path = self.account(age=90000)
        backend = Backend('user@example.com')
        with patch('retention.subprocess.run', side_effect=[subprocess.CompletedProcess([], 0, '0', ''), subprocess.CompletedProcess([], 1, '', '')]):
            self.assertFalse(run(backend, apply=True))
        self.assertNotIn('user@example.com', backend.emails)
        self.assertTrue(path.exists())
        self.assertEqual(retention.pending_jobs(), ['user@example.com'])
        self.assertTrue(run(backend, apply=True))
        self.assertFalse(path.exists())
        self.assertEqual(retention.pending_jobs(), [])

    def test_kick_without_sessions_completes_pending_purge(self):
        path = self.account(age=90000)
        backend = Backend('user@example.com')
        with patch('retention.subprocess.run', side_effect=[
                subprocess.CompletedProcess([], 0, '0', ''),
                subprocess.CompletedProcess([], 1, '', '')]):
            self.assertFalse(run(backend, apply=True))
        self.assertTrue(path.exists())
        with patch('retention.subprocess.run', side_effect=[
                subprocess.CompletedProcess([], 0, '0', ''),
                subprocess.CompletedProcess([], 68, 'no users kicked\n', '')]):
            with retention.operation_lock():
                retention.purge_mailbox(backend, 'user@example.com')
        self.assertFalse(path.exists())
        self.assertEqual(retention.pending_jobs(), [])

    def test_cache_flush_no_user_is_still_a_failure(self):
        path = self.account(age=90000)
        backend = Backend('user@example.com')
        with patch('retention.subprocess.run', side_effect=[
                subprocess.CompletedProcess([], 0, '1M', ''),
                subprocess.CompletedProcess([], 68, '', 'cache failure')]):
            with retention.operation_lock():
                with self.assertRaisesRegex(ValueError, 'session/cache cleanup failed'):
                    retention.purge_mailbox(backend, 'user@example.com')
        self.assertTrue(path.exists())
        self.assertEqual(retention.pending_jobs(), ['user@example.com'])

    def test_recreated_account_not_removed_by_pending_job(self):
        path = self.account(age=90000)
        backend = Backend('user@example.com')
        with patch('retention.subprocess.run', side_effect=[subprocess.CompletedProcess([], 0, '0', ''), subprocess.CompletedProcess([], 1, '', '')]):
            self.assertFalse(run(backend, apply=True))
        backend.emails.add('user@example.com')
        self.assertFalse(run(backend, apply=True))
        self.assertIn('user@example.com', backend.emails)
        self.assertTrue(path.exists())

    def test_same_address_starts_over_only_after_full_deletion(self):
        path = self.account(age=90000)
        backend = Backend('user@example.com')
        self.assertTrue(run(backend, apply=True))
        self.account()
        backend.emails.add('user@example.com')
        self.assertIsNone(retention.read_login('user@example.com'))
        self.assertTrue(run(backend, apply=True))
        self.assertTrue(path.exists())

    def test_paths_cannot_escape_mail_root(self):
        for address in ('../root@example.com', 'x@../../etc', '-x@example.com', 'x@example.com/..'):
            with self.assertRaises(ValueError):
                retention.mailbox(address)

    def test_partial_database_failure_requires_manual_review(self):
        path = self.account(age=90000)
        backend = Backend('user@example.com')
        call = backend.call
        def fail_delete(action, **data):
            if action == 'delete':
                raise RuntimeError('Unknown deletion result')
            return call(action, **data)
        with patch.object(backend, 'call', side_effect=fail_delete):
            self.assertFalse(run(backend, apply=True))
        self.assertFalse(run(backend, apply=True))
        self.assertTrue(path.exists())
        self.assertIn('user@example.com', backend.emails)


if __name__ == '__main__':
    unittest.main()
