import argparse
import getpass
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import cleanup
import retention
import management

BASE = Path(__file__).resolve().parent
DOMAIN = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z')
USER = re.compile(r'[a-z0-9][a-z0-9._+-]{0,63}\Z')


class PanelError(Exception):
    pass


class MailBackend:
    def __init__(self, mode, db_path):
        self.mode = mode
        self.db_path = db_path
        if mode == 'demo':
            with sqlite3.connect(db_path) as db:
                db.execute('CREATE TABLE IF NOT EXISTS emails (email TEXT PRIMARY KEY)')

    def call(self, action, **data):
        if self.mode == 'demo':
            with sqlite3.connect(self.db_path) as db:
                if action in ('list', 'inventory'):
                    return [r[0] for r in db.execute('SELECT email FROM emails ORDER BY email')
                            if action == 'inventory' or r[0].endswith('@' + data['domain'])]
                if action == 'create':
                    try:
                        db.execute('INSERT INTO emails VALUES (?)', (data['user'] + '@' + data['domain'],))
                    except sqlite3.IntegrityError:
                        raise PanelError('الحساب موجود بالفعل.')
                else:
                    db.execute('DELETE FROM emails WHERE email = ?', (data['email'],))
                return {'ok': True}
        try:
            result = subprocess.run(
                [os.environ.get('PANEL_CYBER_PYTHON', '/usr/local/CyberCP/bin/python'),
                 str(BASE / 'cyber_bridge.py')],
                input=json.dumps({'action': action, **data}), text=True,
                capture_output=True, timeout=60, cwd='/usr/local/CyberCP', check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise PanelError('تعذر الاتصال بـCyberPanel. راجع مسار Python وصلاحيات الخدمة.')
        marker = 'MAIL_PANEL_RESULT='
        lines = [line[len(marker):] for line in result.stdout.splitlines() if line.startswith(marker)]
        if result.returncode or not lines:
            raise PanelError('فشل تنفيذ CyberPanel. راجع توافق الإصدار وإعدادات البريد على السيرفر.')
        try:
            value = json.loads(lines[-1])
        except ValueError:
            raise PanelError('رد CyberPanel غير صالح.')
        if action in ('list', 'inventory'):
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise PanelError('قائمة البريد غير صالحة.')
        elif not isinstance(value, dict) or value.get('ok') is not True:
            raise PanelError('رفض CyberPanel العملية. تأكد من وجود الدومين وحدود حسابات البريد.')
        return value


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get('PANEL_SECRET', ''),
        PASSWORD_HASH=os.environ.get('PANEL_PASSWORD_HASH', ''),
        MODE=os.environ.get('PANEL_MODE', 'cyberpanel'),
        DOMAINS=[d.strip().lower() for d in os.environ.get('PANEL_DOMAINS', '').split(',') if d.strip()],
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_SECURE=os.environ.get('PANEL_SECURE_COOKIE') == '1',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30), MAX_CONTENT_LENGTH=262144,
        DB_PATH=str(BASE / 'instance' / 'demo.sqlite3'),
    )
    if overrides:
        app.config.update(overrides)
    if len(app.config['SECRET_KEY']) < 32 or not app.config['PASSWORD_HASH']:
        raise RuntimeError('Set PANEL_SECRET (32+ characters) and PANEL_PASSWORD_HASH. See README.md.')
    if app.config['MODE'] not in ('demo', 'cyberpanel'):
        raise RuntimeError('PANEL_MODE must be demo or cyberpanel')
    if not app.config['DOMAINS'] or any(not DOMAIN.fullmatch(d) for d in app.config['DOMAINS']):
        raise RuntimeError('Set PANEL_DOMAINS to a comma-separated list of existing domains.')
    if app.config['MODE'] == 'demo':
        Path(app.config['DB_PATH']).parent.mkdir(parents=True, exist_ok=True)
    backend = MailBackend(app.config['MODE'], app.config['DB_PATH'])
    store_path = app.config.get('MANAGEMENT_DB') or (app.config['DB_PATH'] + '.managed' if app.config['MODE'] == 'demo'
                    else os.environ.get('PANEL_MANAGEMENT_DB', '/var/lib/mail-panel/managed.sqlite3'))
    store = management.Store(store_path, app.config['SECRET_KEY'])
    app.extensions['management_store'] = store
    app.extensions['mail_backend'] = backend
    mutation_lock = threading.Lock()
    attempts, previews = {}, {}
    state_lock = threading.Lock()
    delete_plans, public_attempts = {}, {}

    @app.before_request
    def protect():
        if request.path.startswith('/api/'):
            if request.path not in ('/api/login', '/api/session') and not session.get('authenticated'):
                return jsonify(error='سجل الدخول أولًا.'), 401
            if request.method == 'POST':
                expected = session.get('csrf', '')
                supplied = request.headers.get('X-CSRF-Token', '')
                if not expected or not secrets.compare_digest(expected, supplied):
                    return jsonify(error='انتهت صلاحية الطلب. حدّث الصفحة.'), 403
                if not request.is_json or not isinstance(request.get_json(silent=True), dict):
                    return jsonify(error='طلب غير صالح.'), 400

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.errorhandler(PanelError)
    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(500)
    def internal(error):
        return jsonify(error='حدث خطأ داخلي. راجع سجل الخدمة.'), 500

    @app.get('/')
    def index():
        return render_template('index.html')

    @app.get('/inbox')
    def public_inbox():
        return render_template('inbox.html')

    @app.post('/public-api/messages')
    def public_messages():
        if not request.is_json or not isinstance(request.get_json(silent=True), dict):
            return jsonify(error='طلب غير صالح.'), 400
        now = time.monotonic()
        with state_lock:
            for ip in list(public_attempts):
                public_attempts[ip] = [t for t in public_attempts[ip] if now - t < 60]
                if not public_attempts[ip]:
                    del public_attempts[ip]
            ip = request.remote_addr
            if len(public_attempts.get(ip, [])) >= 30 or len(public_attempts) > 1024:
                return jsonify(error='طلبات كثيرة؛ انتظر دقيقة.'), 429
            public_attempts.setdefault(ip, []).append(now)
        address = request.json.get('email', '')
        if not isinstance(address, str) or len(address) > 254:
            return jsonify(error='صندوق غير متاح.'), 404
        account = store.account(address)
        if not account or not account['public']:
            return jsonify(error='صندوق غير متاح.'), 404
        try:
            domain = address.rsplit('@', 1)[1]
            if address not in backend.call('list', domain=domain):
                management.forget(store.path, address)
                return jsonify(error='صندوق غير متاح.'), 404
            if app.config['MODE'] == 'demo':
                return jsonify(messages=[], demo=True)
            from inbox_reader import read_messages
            return jsonify(messages=read_messages(address, account['password']), demo=False)
        except Exception:
            return jsonify(error='تعذر قراءة البريد. قد يكون الحساب منتهيًا أو إعداد IMAP يحتاج مراجعة.'), 502

    @app.get('/api/session')
    def session_info():
        return jsonify(authenticated=bool(session.get('authenticated')),
                       csrf=session.setdefault('csrf', secrets.token_urlsafe(32)))

    @app.post('/api/login')
    def login():
        now = time.monotonic()
        ip = request.remote_addr
        with state_lock:
            for key in list(attempts):
                attempts[key] = [t for t in attempts[key] if now - t < 300]
                if not attempts[key]:
                    del attempts[key]
            if len(attempts.get(ip, [])) >= 5:
                return jsonify(error='محاولات كثيرة. انتظر 5 دقائق.'), 429
            attempts.setdefault(ip, []).append(now)
        password = request.json.get('password', '')
        if not isinstance(password, str) or not check_password_hash(app.config['PASSWORD_HASH'], password):
            return jsonify(error='كلمة المرور غير صحيحة.'), 401
        with state_lock:
            attempts.pop(ip, None)
        session.clear()
        session.update(authenticated=True, csrf=secrets.token_urlsafe(32), sid=secrets.token_urlsafe(32))
        session.permanent = True
        return jsonify(csrf=session['csrf'])

    @app.post('/api/logout')
    def logout():
        with state_lock:
            previews.pop(session.get('sid'), None)
        session.clear()
        return jsonify(ok=True)

    def domain_value(value):
        if value not in app.config['DOMAINS']:
            raise ValueError('الدومين غير مسموح.')
        return value

    @app.get('/api/status')
    def status():
        disk = shutil.disk_usage('/')
        return jsonify(mode=app.config['MODE'], domains=app.config['DOMAINS'],
                       disk={'total': disk.total, 'used': disk.used, 'free': disk.free},
                       policies=[{'id': 'all', 'label': 'تنظيف شامل: اللوجات المؤرشفة وكاش الحزم'}] +
                                [{'id': k, 'label': v[0]} for k, v in cleanup.POLICIES.items()])

    @app.get('/api/emails')
    def emails():
        domain = domain_value(request.args.get('domain'))
        return jsonify(emails=backend.call('list', domain=domain))

    @app.get('/api/accounts')
    def accounts():
        domain = domain_value(request.args.get('domain'))
        addresses = sorted(backend.call('list', domain=domain))
        webmail = os.environ.get('PANEL_WEBMAIL_URL', 'https://mail.jxil.org')
        if urlparse(webmail).scheme != 'https' or not urlparse(webmail).hostname:
            webmail = 'https://mail.jxil.org'
        rows = []
        for index, address in enumerate(addresses, 1):
            account = store.account(address)
            rows.append({'number': index, 'email': address,
                         'password': account['password'] if account else None,
                         'public': bool(account and account['public']), 'webmail_url': webmail})
        return jsonify(accounts=rows)

    @app.get('/api/jobs')
    def jobs():
        return jsonify(jobs=store.jobs())

    @app.post('/api/jobs/cancel')
    def cancel_job():
        job = request.json.get('job')
        if not isinstance(job, str) or len(job) > 64:
            raise ValueError('رقم دفعة غير صالح.')
        store.cancel(job)
        return jsonify(ok=True)

    @app.post('/api/bulk/create')
    def bulk_create():
        data = request.json
        domain = domain_value(data.get('domain'))
        count = data.get('count')
        if type(count) is not int or not 1 <= count <= 2000:
            raise ValueError('العدد يجب أن يكون من 1 إلى 2000.')
        prefix = data.get('prefix', 'mail')
        if not isinstance(prefix, str) or not re.fullmatch(r'[a-z][a-z0-9]{0,15}', prefix):
            raise ValueError('بادئة الاسم: حروف إنجليزية صغيرة وأرقام، بحد أقصى 16 حرفًا.')
        public = data.get('public') is True
        if public and data.get('confirmation') != 'صناديق عامة':
            raise ValueError('تفعيل القراءة بالإيميل فقط يحتاج تأكيد «صناديق عامة».')
        key = data.get('request_id')
        if not isinstance(key, str) or not re.fullmatch(r'[a-zA-Z0-9-]{16,80}', key):
            raise ValueError('حدّث الصفحة للحصول على معرف طلب صالح.')
        if shutil.disk_usage('/').free < 300 * 1024 ** 2:
            raise ValueError('المساحة المتاحة أقل من 300 ميجابايت؛ نظف القرص أولًا.')
        suffix = secrets.token_hex(5)
        addresses = [f'{prefix}{suffix}{n}@{domain}' for n in range(1, count + 1)]
        passwords = {address: secrets.token_urlsafe(18) for address in addresses}
        job = store.enqueue('create', addresses, key, passwords, public)
        return jsonify(job=job, count=count), 202

    @app.post('/api/bulk/delete/preview')
    def bulk_delete_preview():
        data = request.json
        domain = domain_value(data.get('domain'))
        current = sorted(backend.call('list', domain=domain))
        count = data.get('count', 0)
        if type(count) is not int or not 0 <= count <= 2000:
            raise ValueError('العدد يجب أن يكون من 0 إلى 2000.')
        selected = data.get('emails', [])
        if not isinstance(selected, list) or len(selected) > 2000 or not all(isinstance(e, str) for e in selected):
            raise ValueError('قائمة حسابات غير صالحة.')
        emails = current[:count] if count else sorted(set(selected))
        if not emails or len(emails) > 2000 or not set(emails).issubset(current):
            raise ValueError('حدد حسابات موجودة للحذف.')
        token = secrets.token_urlsafe(24)
        identities = {}
        if app.config['MODE'] == 'cyberpanel':
            for email in emails:
                try:
                    info = os.stat(retention.mailbox(email), follow_symlinks=False)
                    identities[email] = [info.st_dev, info.st_ino]
                except FileNotFoundError:
                    identities[email] = None
        with state_lock:
            for sid in list(delete_plans):
                if now_age(delete_plans[sid]['time']) > 300:
                    del delete_plans[sid]
            delete_plans[session['sid']] = {'token': token, 'emails': emails, 'identities': identities, 'time': time.monotonic()}
        return jsonify(token=token, emails=emails, confirmation=f'حذف {len(emails)} حساب')

    @app.post('/api/bulk/delete/execute')
    def bulk_delete_execute():
        with state_lock:
            plan = delete_plans.pop(session['sid'], None)
        if (not plan or now_age(plan['time']) > 300 or request.json.get('token') != plan['token']
                or request.json.get('confirmation') != f"حذف {len(plan['emails'])} حساب"):
            raise ValueError('اعمل معاينة جديدة وأكد العدد المعروض.')
        return jsonify(job=store.enqueue('delete', plan['emails'], secrets.token_hex(16), identities=plan['identities'])), 202

    def now_age(timestamp):
        return time.monotonic() - timestamp

    @app.post('/api/accounts/public')
    def toggle_public():
        address = request.json.get('email')
        if not isinstance(address, str):
            raise ValueError('عنوان غير صالح.')
        domain_value(address.rsplit('@', 1)[-1])
        enabled = request.json.get('enabled') is True
        if enabled and request.json.get('confirmation') != address:
            raise ValueError('اكتب العنوان لتأكيد أن أي شخص يعرفه سيقرأ رسائله.')
        if not store.account(address) or address not in backend.call('list', domain=address.rsplit('@', 1)[1]):
            raise ValueError('الحساب غير مُدار بكلمة مرور محفوظة في البانل.')
        with store.db() as db:
            db.execute('UPDATE accounts SET public=? WHERE email=?', (int(enabled), address))
        return jsonify(ok=True)

    @app.get('/api/retention')
    def retention_status():
        if app.config['MODE'] == 'demo':
            return jsonify(mode='demo', accounts=[], pending=[], monitoring='not_verified')
        accounts = []
        for email in backend.call('inventory'):
            try:
                marker = retention.read_login(email)
                accounts.append({'email': email, 'first_login': marker['first_login'] if marker else None,
                                 'expires_at': marker['first_login'] + retention.TTL if marker else None})
            except (OSError, ValueError):
                accounts.append({'email': email, 'error': 'تعذر قراءة سجل أول دخول؛ لن يُحذف تلقائيًا.'})
        return jsonify(mode='cyberpanel', accounts=accounts, pending=retention.pending_jobs(),
                       monitoring='not_verified')

    @app.post('/api/emails/create')
    def create_email():
        data = request.json
        domain = domain_value(data.get('domain'))
        user, password = data.get('user', ''), data.get('password', '')
        if not isinstance(user, str) or not USER.fullmatch(user):
            raise ValueError('اسم البريد يجب أن يكون بحروف إنجليزية صغيرة، بدون مسافات.')
        if not isinstance(password, str) or not 12 <= len(password) <= 128 or '\x00' in password:
            raise ValueError('كلمة مرور البريد يجب أن تكون من 12 إلى 128 حرفًا.')
        with mutation_lock:
            if app.config['MODE'] == 'cyberpanel':
                with retention.operation_lock():
                    if retention.job_path(user + '@' + domain).exists():
                        raise PanelError('هناك حذف غير مكتمل لهذا العنوان. راجع الخدمة قبل إعادة إنشاء الحساب.')
                    if os.path.lexists(retention.mailbox(user + '@' + domain)):
                        raise PanelError('هناك مجلد بريد موجود بهذا العنوان. راجعه قبل إنشاء حساب قد يرث بيانات قديمة.')
                    if user + '@' + domain in backend.call('list', domain=domain):
                        raise PanelError('الحساب موجود بالفعل؛ لم تتغير كلمة مروره.')
                    store.save(user + '@' + domain, password)
                    backend.call('create', domain=domain, user=user, password=password)
            else:
                backend.call('create', domain=domain, user=user, password=password)
                store.save(user + '@' + domain, password)
            if user + '@' + domain not in backend.call('list', domain=domain):
                raise PanelError('لم يتم التأكد من إنشاء الحساب. حدّث القائمة قبل المحاولة مجددًا.')
        app.logger.warning('Email created: %s@%s', user, domain)
        store.status(user + '@' + domain, 'active')
        return jsonify(ok=True)

    @app.post('/api/emails/delete')
    def delete_email():
        email = request.json.get('email', '')
        if not isinstance(email, str) or email.count('@') != 1:
            raise ValueError('عنوان بريد غير صالح.')
        user, domain = email.rsplit('@', 1)
        domain_value(domain)
        if not USER.fullmatch(user) or request.json.get('confirmation') != email:
            raise ValueError('اكتب عنوان البريد كاملًا لتأكيد الحذف.')
        with mutation_lock:
            if email not in backend.call('list', domain=domain):
                raise ValueError('الحساب غير موجود. حدّث القائمة.')
            if app.config['MODE'] == 'cyberpanel':
                try:
                    with retention.operation_lock():
                        retention.purge_mailbox(backend, email)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    raise PanelError('الحذف غير مكتمل وقد أُزيل الحساب بالفعل. تم حفظ العملية لإعادة المحاولة؛ راجع قائمة الحذف المعلق وخدمة Dovecot.')
            else:
                backend.call('delete', email=email)
            if email in backend.call('list', domain=domain):
                raise PanelError('لم يتم التأكد من حذف الحساب. حدّث القائمة.')
        app.logger.warning('Email deleted: %s', email)
        management.forget(store.path, email)
        return jsonify(ok=True)

    @app.post('/api/cleanup/preview')
    def cleanup_preview():
        if app.config['MODE'] == 'demo':
            raise ValueError('تنظيف السيرفر متاح في الوضع الفعلي فقط؛ الوضع التجريبي لا يحذف ملفات.')
        category = request.json.get('category')
        if not isinstance(category, str) or (category != 'all' and category not in cleanup.POLICIES):
            raise ValueError('فئة تنظيف غير صالحة.')
        try:
            result = cleanup.preview_all() if category == 'all' else cleanup.preview(category)
        except PermissionError:
            raise PanelError('الخدمة لا تملك صلاحية قراءة هذا المسار.')
        token = secrets.token_urlsafe(24)
        with state_lock:
            for sid in list(previews):
                if time.monotonic() - previews[sid]['time'] > 300:
                    del previews[sid]
            previews[session['sid']] = dict(token=token, time=time.monotonic(),
                                           category=category, files=result['files'])
        return jsonify(**result, token=token)

    @app.post('/api/cleanup/execute')
    def cleanup_execute():
        if app.config['MODE'] == 'demo':
            raise ValueError('التنظيف معطل في الوضع التجريبي.')
        with state_lock:
            plan = previews.pop(session['sid'], None)
        if (not plan or time.monotonic() - plan['time'] > 300 or
                request.json.get('token') != plan['token'] or request.json.get('confirmation') != 'حذف'):
            raise ValueError('اعمل معاينة جديدة واكتب «حذف» للتأكيد.')
        try:
            with mutation_lock:
                result = (cleanup.execute_all(plan['files']) if plan['category'] == 'all'
                          else cleanup.execute(plan['category'], plan['files']))
        except OSError:
            raise PanelError('تعذر فتح مسار التنظيف. اعمل معاينة جديدة وراجع الصلاحيات.')
        app.logger.warning('Cleanup category=%s deleted=%s skipped=%s',
                           plan['category'], result['deleted'], result['skipped'])
        return jsonify(**result)

    return app


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hash-password', action='store_true')
    args = parser.parse_args()
    if args.hash_password:
        password = getpass.getpass('Admin password (12+ characters): ')
        if len(password) < 12:
            parser.error('Use at least 12 characters')
        print(generate_password_hash(password))
    else:
        from waitress import serve
        host = os.environ.get('PANEL_HOST', '127.0.0.1')
        if host != '127.0.0.1':
            parser.error('Keep PANEL_HOST=127.0.0.1; use an SSH tunnel or HTTPS reverse proxy.')
        app = create_app()
        import bulk_worker
        bulk_worker.start(app)
        serve(app, host=host, port=int(os.environ.get('PANEL_PORT', '8095')), threads=4)
