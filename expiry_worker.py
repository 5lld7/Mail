"""One retention pass; scheduled by systemd, independently of the web panel."""
import argparse
import json
import os
import time

from app import MailBackend
import retention


def run(backend, apply=False):
    failed = False
    with retention.operation_lock():
        inventory = backend.call('inventory')
        pending = set(retention.pending_jobs())
        for email in sorted(set(inventory) | pending):
            try:
                marker = retention.read_login(email)
                due = marker is not None and time.time() >= marker['first_login'] + retention.TTL
                if email not in pending and not due:
                    continue
                if not apply:
                    print(json.dumps({'email': email, 'due': due, 'pending': email in pending}))
                    continue
                retention.purge_mailbox(backend, email, expected_token=marker['token'] if marker else None)
                print(json.dumps({'email': email, 'deleted': True}))
            except Exception as error:
                failed = True
                print(json.dumps({'email': email, 'error': 'Deletion not completed; review paths, pending jobs and Dovecot health',
                                  'reason': str(error) if isinstance(error, (ValueError, OSError)) else type(error).__name__}))
    return not failed


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true', help='Permanently delete expired accounts and mail data')
    args = parser.parse_args()
    if os.environ.get('PANEL_MODE', 'cyberpanel') != 'cyberpanel':
        parser.error('Expiry worker only supports real CyberPanel mode')
    backend = MailBackend('cyberpanel', '')
    raise SystemExit(0 if run(backend, apply=args.apply) else 1)
