"""Real Waitress HTTP smoke test with temporary, in-memory-only credentials."""
import http.cookiejar
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from werkzeug.security import generate_password_hash

ROOT = Path(__file__).resolve().parents[1]


def main():
    password = secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory() as temp:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        env = dict(os.environ, PANEL_SECRET=secrets.token_hex(32), PANEL_MODE='demo',
                   PANEL_PASSWORD_HASH=generate_password_hash(password),
                   PANEL_DOMAINS='example.com', PANEL_SECURE_COOKIE='0')
        command = ('from app import create_app; from waitress import serve; '
                   f'serve(create_app({{"DB_PATH": {str(Path(temp) / "demo.db")!r}}}), '
                   f'host="127.0.0.1", port={port}, threads=2)')
        process = subprocess.Popen([sys.executable, '-c', command], cwd=ROOT, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        base = f'http://127.0.0.1:{port}'
        csrf = ''

        def api(path, data=None):
            req = urllib.request.Request(base + '/api/' + path,
                data=json.dumps(data).encode() if data is not None else None,
                headers={'Content-Type': 'application/json', 'X-CSRF-Token': csrf})
            with opener.open(req, timeout=10) as response:
                return json.load(response)

        try:
            for _ in range(50):
                try:
                    bootstrap = api('session')
                    break
                except urllib.error.URLError:
                    if process.poll() is not None:
                        raise RuntimeError('Server failed to start')
                    time.sleep(.1)
            else:
                raise RuntimeError('Server did not become ready')
            csrf = bootstrap['csrf']
            try:
                api('status')
                raise AssertionError('Unauthenticated status should fail')
            except urllib.error.HTTPError as error:
                assert error.code == 401
            csrf = api('login', {'password': password})['csrf']
            assert api('status')['mode'] == 'demo'
            for asset in ('/', '/static/app.js', '/static/style.css'):
                with opener.open(base + asset) as response:
                    assert response.status == 200 and len(response.read()) > 100
            api('emails/create', {'user': 'smoke123', 'domain': 'example.com', 'password': 'Abcd1234'})
            assert api('emails?domain=example.com')['emails'] == ['smoke123@example.com']
            api('emails/delete', {'email': 'smoke123@example.com', 'confirmation': 'smoke123@example.com'})
            assert api('emails?domain=example.com')['emails'] == []
            api('logout', {})
            print('PASS: real HTTP startup, auth, assets, disk status, create/list/delete, logout')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
