"""Mailbox login markers and recoverable, narrowly scoped mailbox purges."""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import time
from pathlib import Path

MAIL_ROOT = Path('/home/vmail')
STATE_ROOT = Path('/var/lib/mail-panel')
MARKER = '.mail-panel-first-login.json'
TTL = 86400
LOCAL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}\Z')
DOMAIN = re.compile(r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z')


def parts(email):
    if not isinstance(email, str) or email.count('@') != 1:
        raise ValueError('Invalid mailbox address')
    user, domain = email.rsplit('@', 1)
    if not LOCAL.fullmatch(user) or not DOMAIN.fullmatch(domain):
        raise ValueError('Unsupported mailbox address')
    return user, domain


def mailbox(email):
    user, domain = parts(email)
    path = MAIL_ROOT / domain / user
    if path.resolve() != path or MAIL_ROOT.resolve() != MAIL_ROOT:
        raise ValueError('Mailbox path contains a symlink')
    return path


@contextlib.contextmanager
def mailbox_fd(email):
    path = mailbox(email)
    root = os.open(MAIL_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    domain = user = None
    try:
        domain = os.open(path.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        user = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=domain)
        yield user, domain, path.name
    finally:
        for fd in (user, domain, root):
            if fd is not None:
                os.close(fd)


def record_login(email):
    """Called by Dovecot post-login, once per successful IMAP/POP3 login."""
    with mailbox_fd(email) as (fd, _, __):
        try:
            marker = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=fd)
        except FileExistsError:
            return  # Repeated logins never restart the 24-hour countdown.
        with os.fdopen(marker, 'w') as stream:
            json.dump({'email': email, 'first_login': int(time.time()),
                       'token': secrets.token_hex(24)}, stream)
            stream.flush()
            os.fsync(stream.fileno())


def read_login(email, now=None):
    now = time.time() if now is None else now
    try:
        with mailbox_fd(email) as (fd, _, __):
            marker = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(marker) as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096
                        or info.st_uid != os.fstat(fd).st_uid):
                    raise ValueError('Invalid first-login marker')
                data = json.load(stream)
            if (not isinstance(data, dict) or data.get('email') != email or not isinstance(data.get('first_login'), int)
                    or not 1577836800 <= data['first_login'] <= now + 60
                    or not isinstance(data.get('token'), str) or len(data['token']) != 48):
                raise ValueError('Invalid first-login timestamp')
            return data
    except FileNotFoundError:
        return None


@contextlib.contextmanager
def operation_lock():
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = os.open(STATE_ROOT / 'operations.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        os.close(lock)


def job_path(email):
    return STATE_ROOT / (hashlib.sha256(email.encode()).hexdigest() + '.json')


def write_job(job):
    path = job_path(job['email'])
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(job, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(STATE_ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def remove_contents(fd, device):
    """FD-relative deletion: do not follow symlinks or cross filesystems."""
    for name in os.listdir(fd):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if info.st_dev != device:
            raise ValueError('Refusing mounted mailbox content')
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError('Mailbox changed during deletion')
                remove_contents(child, device)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)


def purge_mailbox(backend, email, expected_token=None):
    """Must be called with operation_lock held. Jobs survive process failures."""
    doveadm = shutil.which('doveadm')
    doveconf = shutil.which('doveconf')
    if not doveadm or not doveconf:
        raise ValueError('Dovecot administrative tools are missing')
    cache = subprocess.run([doveconf, '-h', 'auth_cache_size'], capture_output=True,
                           text=True, timeout=15, check=False)
    if cache.returncode != 0:
        raise ValueError('Cannot verify Dovecot authentication cache configuration')
    cache_disabled = bool(re.fullmatch(r'0\s*[bB]?', cache.stdout.strip()))
    path = mailbox(email)
    pending = job_path(email)
    resuming = pending.exists()
    if resuming:
        with pending.open() as stream:
            job = json.load(stream)
        if job.get('email') != email:
            raise ValueError('Invalid pending purge')
    else:
        if expected_token is not None:
            marker = read_login(email)
            if (not marker or marker['token'] != expected_token
                    or time.time() < marker['first_login'] + TTL):
                raise ValueError('Mailbox is not due for deletion')
        try:
            with mailbox_fd(email) as (fd, _, __):
                info = os.fstat(fd)
                identity = [info.st_dev, info.st_ino]
        except FileNotFoundError:
            identity = None
        job = {'email': email, 'identity': identity, 'database_deleted': False}
        write_job(job)
    # A recreated or moved mailbox must never inherit an old purge job.
    try:
        with mailbox_fd(email) as (fd, _, __):
            info = os.fstat(fd)
            if [info.st_dev, info.st_ino] != job['identity']:
                raise ValueError('Mailbox was replaced; manual review required')
    except FileNotFoundError:
        pass
    domain = email.rsplit('@', 1)[1]
    existing = backend.call('list', domain=domain)
    if job['database_deleted'] and email in existing:
        raise ValueError('Mailbox was recreated; pending purge paused')
    if resuming and job.get('database_started') and not job['database_deleted'] and email in existing:
        raise ValueError('Previous database deletion result unknown; manual review required')
    if email in existing:
        job['database_started'] = True
        write_job(job)
        backend.call('delete', email=email)
        if email in backend.call('list', domain=domain):
            raise ValueError('CyberPanel did not delete the account')
    job['database_deleted'] = True
    write_job(job)
    commands = [['kick', email]]
    if not cache_disabled:
        commands.insert(0, ['auth', 'cache', 'flush', email])
    for args in commands:
        result = subprocess.run([doveadm, *args], capture_output=True, text=True, timeout=30, check=False)
        # doveadm kick uses EX_NOUSER (68) when there are no matching
        # sessions. There is then nothing to disconnect; cache failures
        # and all other kick failures must still preserve mailbox data.
        no_sessions = args[0] == 'kick' and result.returncode == 68
        if result.returncode != 0 and not no_sessions:
            raise ValueError('Dovecot session/cache cleanup failed; mailbox data retained for retry')
    if email in backend.call('list', domain=domain):
        raise ValueError('Mailbox was recreated during purge; deletion paused')
    try:
        with mailbox_fd(email) as (fd, domain_fd, name):
            info = os.fstat(fd)
            if [info.st_dev, info.st_ino] != job['identity']:
                raise ValueError('Mailbox was replaced; deletion paused')
            remove_contents(fd, info.st_dev)
            os.rmdir(name, dir_fd=domain_fd)
    except FileNotFoundError:
        pass
    if os.path.lexists(path):
        raise ValueError('Mailbox data remains; purge incomplete')
    import management
    management.forget(os.environ.get('PANEL_MANAGEMENT_DB', str(STATE_ROOT / 'managed.sqlite3')), email)
    pending.unlink()


def pending_jobs():
    if not STATE_ROOT.exists():
        return []
    jobs = []
    for path in STATE_ROOT.glob('*.json'):
        with path.open() as stream:
            jobs.append(json.load(stream)['email'])
    return jobs
