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

from flask import Flask, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import cleanup

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
                if action == 'list':
                    return [r[0] for r in db.execute('SELECT email FROM emails ORDER BY email')
                            if r[0].endswith('@' + data['domain'])]
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
        if action == 'list':
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
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30), MAX_CONTENT_LENGTH=16384,
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
    mutation_lock = threading.Lock()
    attempts, previews = {}, {}
    state_lock = threading.Lock()

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
                       policies=[{'id': k, 'label': v[0]} for k, v in cleanup.POLICIES.items()])

    @app.get('/api/emails')
    def emails():
        domain = domain_value(request.args.get('domain'))
        return jsonify(emails=backend.call('list', domain=domain))

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
            backend.call('create', domain=domain, user=user, password=password)
            if user + '@' + domain not in backend.call('list', domain=domain):
                raise PanelError('لم يتم التأكد من إنشاء الحساب. حدّث القائمة قبل المحاولة مجددًا.')
        app.logger.warning('Email created: %s@%s', user, domain)
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
            backend.call('delete', email=email)
            if email in backend.call('list', domain=domain):
                raise PanelError('لم يتم التأكد من حذف الحساب. حدّث القائمة.')
        app.logger.warning('Email deleted: %s', email)
        return jsonify(ok=True)

    @app.post('/api/cleanup/preview')
    def cleanup_preview():
        if app.config['MODE'] == 'demo':
            raise ValueError('تنظيف السيرفر متاح في الوضع الفعلي فقط؛ الوضع التجريبي لا يحذف ملفات.')
        category = request.json.get('category')
        if category not in cleanup.POLICIES:
            raise ValueError('فئة تنظيف غير صالحة.')
        try:
            result = cleanup.preview(category)
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
                result = cleanup.execute(plan['category'], plan['files'])
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
        serve(create_app(), host=host, port=int(os.environ.get('PANEL_PORT', '8095')), threads=4)
