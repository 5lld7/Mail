"""Optional browser smoke test: requires Playwright and a system Chromium."""
import os
import json
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
                'import bulk_worker; bulk_worker.start(app); '
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
                page.locator('#bulk-tab').click()
                page.locator('#bulk-count').fill('3')
                page.locator('#bulk-form button').click()
                expect(page.locator('#jobs-list')).to_contain_text('3 / 3', timeout=20000)
                page.locator('#mail-tab').click()
                page.locator('#refresh').click()
                expect(page.locator('#email-count')).to_have_text('3')
                passwords = page.locator('.account-details input').evaluate_all('(els) => els.map(e => e.value)')
                assert len(set(passwords)) == 3 and all(len(value) >= 24 for value in passwords)
                page.locator('#delete-tab').click()
                expect(page.locator('#delete-list input')).to_have_count(3)
                page.locator('#delete-list input').nth(1).check()
                page.locator('#delete-preview').click()
                expect(page.locator('#delete-summary')).to_contain_text('1 حساب')
                page.locator('#delete-execute').click()
                page.locator('#confirm-input').fill('حذف 1 حساب')
                page.locator('#confirm-submit').click()
                expect(page.locator('#jobs-list')).to_contain_text('1 / 1', timeout=20000)
                page.locator('#mail-tab').click()
                page.locator('#refresh').click()
                expect(page.locator('#email-count')).to_have_text('2')
                first_email = page.locator('.address').first.inner_text()
                page.get_by_role('button', name='جعله صندوقًا عامًا', exact=True).first.click()
                page.locator('#confirm-input').fill(first_email)
                page.locator('#confirm-submit').click()
                expect(page.get_by_role('link', name='الصندوق العام', exact=True)).to_have_count(1)
                public_page = browser.new_page()
                public_page.goto(f'http://127.0.0.1:{port}/inbox')
                public_page.locator('#inbox-email').fill(first_email)
                public_page.locator('#inbox-form button').click()
                expect(public_page.locator('#inbox-status')).to_contain_text('وضع تجريبي')
                public_page.route('**/public-api/messages', lambda route: route.fulfill(content_type='application/json', body=json.dumps({'demo': False, 'messages': [{'subject': '<script>window.pwned=1</script>', 'sender': 'sender@example.com', 'date': '', 'text': '<img src=x onerror=window.pwned=1>', 'limited': False}]})))
                public_page.locator('#inbox-form button').click()
                expect(public_page.locator('#messages h2')).to_have_text('<script>window.pwned=1</script>')
                assert public_page.locator('#messages img').count() == 0
                assert public_page.evaluate('window.pwned === undefined')
                public_page.close()
                page.locator('#cleanup-tab').click()
                page.locator('#preview').click()
                expect(page.locator('#notice')).to_contain_text('تنظيف السيرفر متاح')
                page.locator('#retention-tab').click()
                expect(page.locator('#retention-list')).to_contain_text('لا توجد مراقبة دخول')
                page.set_viewport_size({'width': 390, 'height': 844})
                page.screenshot(path='/tmp/mail-panel-mobile.png', full_page=True)
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile horizontal overflow'
                assert not errors, errors
                page.locator('#logout').click()
                page.locator('#login').wait_for(state='visible')
                browser.close()
                print('PASS: browser login, individual/bulk creation, passwords, selected deletion, public inbox, XSS isolation, mobile layout, logout; no JS errors')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
