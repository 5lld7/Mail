"""Durable bulk jobs and encrypted credentials, shared by the UI and worker."""
import base64
import contextlib
import hashlib
import os
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography.fernet import Fernet


class Store:
    def __init__(self, path, secret):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        self.cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(('mail-panel-vault:' + secret).encode()).digest()))
        with self.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS accounts (
                    email TEXT PRIMARY KEY, password BLOB NOT NULL,
                    public INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
                    status TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY, job TEXT NOT NULL, email TEXT NOT NULL,
                    status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', identity TEXT NOT NULL DEFAULT '');
            ''')
            if 'identity' not in [r['name'] for r in db.execute('PRAGMA table_info(tasks)')]:
                db.execute("ALTER TABLE tasks ADD COLUMN identity TEXT NOT NULL DEFAULT ''")

    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA secure_delete=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, email, password, public=False, status='creating'):
        encrypted = self.cipher.encrypt(password.encode())
        with self.db() as db:
            db.execute('INSERT INTO accounts VALUES (?,?,?,?) ON CONFLICT(email) DO UPDATE SET password=excluded.password, public=excluded.public, status=excluded.status',
                       (email, encrypted, int(public), status))

    def account(self, email):
        with self.db() as db:
            row = db.execute('SELECT * FROM accounts WHERE email=?', (email,)).fetchone()
        if not row or row['status'] != 'active':
            return None
        result = dict(row)
        result['password'] = self.cipher.decrypt(result['password']).decode()
        return result

    def status(self, email, status):
        with self.db() as db:
            db.execute('UPDATE accounts SET status=? WHERE email=?', (status, email))

    def enqueue(self, kind, emails, request_id, passwords=None, public=False, identities=None):
        with self.db() as db:
            existing = db.execute('SELECT id FROM jobs WHERE request_id=?', (request_id,)).fetchone()
            if existing:
                return existing['id']
            job = secrets.token_hex(12)
            db.execute('INSERT INTO jobs VALUES (?,?,?,?,?)', (job, request_id, kind, 'queued', time.time()))
            for email in emails:
                if kind == 'create':
                    # Never overwrite credentials of an existing managed account.
                    db.execute('INSERT INTO accounts VALUES (?,?,?,?)',
                               (email, self.cipher.encrypt(passwords[email].encode()), int(public), 'creating'))
                import json
                identity = json.dumps((identities or {}).get(email)) if kind == 'delete' else ''
                db.execute('INSERT INTO tasks(job,email,status,identity) VALUES (?,?,?,?)', (job, email, 'queued', identity))
        return job

    def jobs(self):
        with self.db() as db:
            rows = db.execute('SELECT * FROM jobs ORDER BY created DESC LIMIT 30').fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item['counts'] = {r['status']: r['n'] for r in db.execute('SELECT status,count(*) n FROM tasks WHERE job=? GROUP BY status', (row['id'],))}
                item['errors'] = [dict(r) for r in db.execute("SELECT email,error FROM tasks WHERE job=? AND status IN ('error','uncertain') LIMIT 5", (row['id'],))]
                result.append(item)
            return result

    def recover(self):
        with self.db() as db:
            db.execute("UPDATE jobs SET status='paused' WHERE id IN (SELECT job FROM tasks WHERE status='running')")
            db.execute("UPDATE tasks SET status='uncertain',error='الخدمة توقفت أثناء التنفيذ؛ راجع الحساب قبل أي إعادة محاولة.' WHERE status='running'")

    def claim(self):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT tasks.*,jobs.kind FROM tasks JOIN jobs ON jobs.id=tasks.job WHERE tasks.status='queued' AND jobs.status IN ('queued','running') ORDER BY tasks.id LIMIT 1").fetchone()
            if not row:
                return None
            db.execute("UPDATE tasks SET status='running' WHERE id=?", (row['id'],))
            db.execute("UPDATE jobs SET status='running' WHERE id=?", (row['job'],))
            return dict(row)

    def finish(self, task, error=None):
        with self.db() as db:
            db.execute('UPDATE tasks SET status=?,error=? WHERE id=?',
                       ('error' if error else 'done', error or '', task['id']))
            if error:
                db.execute("UPDATE jobs SET status='paused' WHERE id=?", (task['job'],))
            elif not db.execute("SELECT 1 FROM tasks WHERE job=? AND status='queued'", (task['job'],)).fetchone():
                db.execute("UPDATE jobs SET status='done' WHERE id=? AND status!='cancelled'", (task['job'],))

    def cancel(self, job):
        with self.db() as db:
            db.execute("UPDATE jobs SET status='cancelled' WHERE id=? AND status!='done'", (job,))
            db.execute("UPDATE accounts SET password=X'',public=0,status='deleted' WHERE status='creating' AND email IN (SELECT email FROM tasks WHERE job=? AND status='queued')", (job,))
            db.execute("UPDATE tasks SET status='cancelled' WHERE job=? AND status='queued'", (job,))


def forget(path, email):
    if not Path(path).exists():
        return
    with sqlite3.connect(path, timeout=15) as db:
        db.execute('PRAGMA secure_delete=ON')
        db.execute("UPDATE accounts SET password=X'',public=0,status='deleted' WHERE email=?", (email,))
