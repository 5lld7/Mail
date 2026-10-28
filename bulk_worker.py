"""Single background worker; durable jobs resume after service restarts."""
import os
import json
import shutil
import threading
import time
from contextlib import nullcontext

import management
import retention


def process_one(store, backend, mode):
    task = store.claim()
    if not task:
        return False
    try:
        email = task['email']
        user, domain = retention.parts(email)
        guard = retention.operation_lock if mode == 'cyberpanel' else nullcontext
        if task['kind'] == 'create':
            if shutil.disk_usage('/').free < 200 * 1024 ** 2:
                raise ValueError('مساحة القرص أقل من 200 ميجابايت؛ الدفعة متوقفة.')
            with guard():
                if email in backend.call('list', domain=domain):
                    raise ValueError('العنوان موجود بالفعل؛ لم يتم تغيير كلمة مروره.')
                if mode == 'cyberpanel' and (retention.job_path(email).exists() or os.path.lexists(retention.mailbox(email))):
                    raise ValueError('هناك بيانات بريد قديمة أو حذف معلق لهذا العنوان.')
                with store.db() as db:
                    row = db.execute('SELECT password FROM accounts WHERE email=?', (email,)).fetchone()
                password = store.cipher.decrypt(row['password']).decode()
                backend.call('create', domain=domain, user=user, password=password)
                if email not in backend.call('list', domain=domain):
                    raise ValueError('تعذر التأكد من إنشاء الحساب؛ راجعه قبل تكرار العملية.')
                store.status(email, 'active')
        else:
            with guard():
                if mode == 'cyberpanel':
                    try:
                        info = os.stat(retention.mailbox(email), follow_symlinks=False)
                        current = [info.st_dev, info.st_ino]
                    except FileNotFoundError:
                        current = None
                    if current != json.loads(task['identity']):
                        raise ValueError('مجلد الحساب اتغير بعد معاينة الحذف؛ اعمل معاينة جديدة.')
                    retention.purge_mailbox(backend, email)
                else:
                    backend.call('delete', email=email)
                management.forget(store.path, email)
        store.finish(task)
    except Exception as error:
        # Never include CLI output or credentials in the job's error text.
        reason = str(error) if isinstance(error, ValueError) else 'راجع حالة الحساب والمساحة وحدود CyberPanel.'
        store.finish(task, 'العملية لم تكتمل: ' + reason + ' الدفعة متوقفة؛ راجع الحساب قبل إعادة المحاولة.')
    return True


def start(app):
    store = app.extensions['management_store']
    backend = app.extensions['mail_backend']
    def loop():
        # Separate lock from mailbox operations; only one job worker per database.
        import fcntl
        fd = os.open(str(store.path) + '.worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return
        store.recover()
        while True:
            try:
                worked = process_one(store, backend, app.config['MODE'])
            except Exception:
                app.logger.error('Bulk worker unavailable; check private state storage and service permissions')
                worked = False
            time.sleep(.2 if worked else 2)
    threading.Thread(target=loop, name='mail-panel-bulk', daemon=True).start()
