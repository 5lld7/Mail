"""Optional browser smoke test: requires Playwright and a system Chromium."""
import os
import secrets
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory() as temp:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        password = secrets.token_urlsafe(24)
        env = dict(os.environ, PANEL_MODE='demo', PANEL_DOMAINS='example.com',
                   PANEL_SECRET=secrets.token_hex(32), PANEL_SECURE_COOKIE='0', SMOKE_PASSWORD=password)
        code = ('import os; from app import create_app; from waitress import serve; '
                'from werkzeug.security import generate_password_hash; '
                f'app=create_app({{"PASSWORD_HASH": generate_password_hash(os.environ["SMOKE_PASSWORD"]), "DB_PATH": {str(Path(temp) / "demo.db")!r}}}); '
                f'serve(app, host="127.0.0.1", port={port}, threads=2)')
        process = subprocess.Popen([str(ROOT / '.venv/bin/python'), '-c', code],
                                   cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                try:
                    with socket.create_connection(('127.0.0.1', port), .1):
                        break
                except OSError:
                    time.sleep(.1)
            with sync_playwright() as p:
                browser = p.chromium.launch(executable_path='/usr/bin/chromium', headless=True,
                                            args=['--no-sandbox'])
                page = browser.new_page(viewport={'width': 1440, 'height': 1050})
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto(f'http://127.0.0.1:{port}')
                page.locator('#admin-password').fill(password)
                page.locator('#login-form button').click()
                page.locator('#dashboard').wait_for(state='visible')
                expect(page.locator('#email-count')).to_have_text('0')
                page.locator('#email-user').fill('browser')
                page.locator('#email-password').fill(secrets.token_urlsafe(18))
                page.locator('#create-form button').click()
                page.get_by_text('browser@example.com', exact=True).wait_for()
                page.screenshot(path='/tmp/mail-panel-desktop.png', full_page=True)
                page.get_by_role('button', name='حذف الحساب', exact=True).click()
                page.locator('#confirm-input').fill('browser@example.com')
                page.locator('#confirm-submit').click()
                expect(page.locator('#email-count')).to_have_text('0')
                page.locator('#cleanup-tab').click()
                page.locator('#preview').click()
                expect(page.locator('#notice')).to_contain_text('تنظيف السيرفر متاح')
                page.set_viewport_size({'width': 390, 'height': 844})
                page.screenshot(path='/tmp/mail-panel-mobile.png', full_page=True)
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile horizontal overflow'
                assert not errors, errors
                page.locator('#logout').click()
                page.locator('#login').wait_for(state='visible')
                browser.close()
                print('PASS: browser login, create/delete confirmation, demo cleanup guard, mobile layout, logout; no JS errors')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
