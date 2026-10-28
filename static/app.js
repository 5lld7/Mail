let csrf = '', statusData = null, plan = null, busy = false, accountRows = [], pageIndex = 0, deletePlan = null, createRequestId = null;
const $ = id => document.getElementById(id);
const bytes = n => { const units = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${units[i]}`; };
function notice(message, error = false) { $('notice').textContent = message; $('notice').className = error ? 'error' : ''; $('notice').hidden = false; }
async function api(path, data) {
  const response = await fetch(`/api/${path}`, {method: data ? 'POST' : 'GET', headers: data ? {'Content-Type': 'application/json', 'X-CSRF-Token': csrf} : {}, body: data ? JSON.stringify(data) : undefined});
  let result; try { result = await response.json(); } catch { throw new Error('رد غير متوقع من السيرفر.'); }
  if (!response.ok) { if (response.status === 401 && path !== 'login') { showLogin(); const s = await api('session'); csrf = s.csrf; } throw new Error(result.error || 'تعذر تنفيذ الطلب.'); }
  return result;
}
async function action(fn) {
  if (busy) return;
  busy = true;
  document.querySelectorAll('button').forEach(b => b.disabled = true);
  try { await fn(); } catch (e) { notice(e.message, true); }
  finally { busy = false; document.querySelectorAll('button').forEach(b => b.disabled = false); }
}
function showLogin() { $('login').hidden = false; $('dashboard').hidden = true; $('logout').hidden = true; }
async function disk() {
  statusData = await api('status');
  const d = statusData.disk;
  $('disk-used').textContent = bytes(d.used); $('disk-free').textContent = bytes(d.free);
  $('disk-total').textContent = `من إجمالي ${bytes(d.total)}`;
  $('disk-bar').style.width = `${d.used / d.total * 100}%`;
}
async function loadEmails() {
  $('email-count').textContent = '—'; $('email-list').replaceChildren();
  const result = await api(`accounts?domain=${encodeURIComponent($('domain').value)}`);
  accountRows = result.accounts; pageIndex = 0; renderAccounts();
}
function renderAccounts() {
  $('email-list').replaceChildren(); $('email-count').textContent = accountRows.length;
  const pages = Math.max(1, Math.ceil(accountRows.length / 100)); pageIndex = Math.max(0, Math.min(pageIndex, pages - 1));
  $('page-label').textContent = `${pageIndex + 1} / ${pages}`;
  if (!accountRows.length) { const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = 'مفيش حسابات بريد على الدومين ده لسه.'; $('email-list').append(empty); }
  for (const account of accountRows.slice(pageIndex * 100, (pageIndex + 1) * 100)) {
    const email = account.email;
    const row = document.createElement('div'); row.className = 'email-row';
    const details = document.createElement('div'); details.className = 'account-details';
    const number = document.createElement('small'); number.textContent = `#${account.number}`;
    const name = document.createElement('span'); name.className = 'address'; name.textContent = email;
    const password = document.createElement('input'); password.type = 'text'; password.readOnly = true; password.dir = 'ltr'; password.autocomplete = 'off'; password.setAttribute('aria-label', `كلمة مرور ${email}`); password.value = account.password || 'كلمة المرور القديمة غير متاحة';
    const link = document.createElement('a'); link.href = account.webmail_url; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = 'دخول الويب ميل';
    details.append(number, name, password, link);
    const actions = document.createElement('div'); actions.className = 'account-actions';
    if (account.password) {
      const toggle = document.createElement('button'); toggle.textContent = account.public ? 'إيقاف القراءة العامة' : 'جعله صندوقًا عامًا';
      toggle.onclick = async () => {
        if (!account.public && !await confirmText('إتاحة الرسائل للجميع؟', 'أي شخص يعرف العنوان سيقرأ رسائله بدون باسورد. اكتب الإيميل لتأكيد ذلك.', email)) return;
        action(async () => { await api('accounts/public', {email, enabled: !account.public, confirmation: email}); await loadEmails(); });
      };
      actions.append(toggle);
      if (account.public) { const publicLink = document.createElement('a'); publicLink.href = `/inbox?email=${encodeURIComponent(email)}`; publicLink.target = '_blank'; publicLink.rel = 'noopener noreferrer'; publicLink.textContent = 'الصندوق العام'; details.append(publicLink); }
    }
    const button = document.createElement('button'); button.className = 'danger'; button.textContent = 'حذف الحساب';
    button.onclick = async () => {
      const confirmed = await confirmText('حذف حساب البريد؟', 'الحذف نهائي وقد يحذف رسائل الحساب. اكتب عنوان البريد كاملًا للتأكيد:', email);
      if (confirmed) await action(async () => { await api('emails/delete', {email, confirmation: email}); notice('تم حذف الحساب.'); await loadEmails(); });
    };
    actions.append(button); row.append(details, actions); $('email-list').append(row);
  }
}
async function dashboard() {
  $('login').hidden = true; $('dashboard').hidden = false; $('logout').hidden = false;
  await disk();
  $('mode').textContent = statusData.mode === 'demo' ? 'وضع تجريبي · بدون اتصال بسيرفر' : 'الوضع الفعلي · CyberPanel';
  $('domain').replaceChildren(...statusData.domains.map(d => new Option(d, d)));
  for (const id of ['bulk-domain', 'delete-domain']) $(id).replaceChildren(...statusData.domains.map(d => new Option(d, d)));
  $('category').replaceChildren(...statusData.policies.map(p => new Option(p.label, p.id)));
  if (statusData.mode === 'demo') notice('أنت في الوضع التجريبي: الحسابات محلية للتجربة فقط، ولا يتم حذف أي ملفات من السيرفر.');
  await loadEmails();
}
function confirmText(title, description, expected) {
  return new Promise(resolve => {
    $('confirm-title').textContent = title; $('confirm-description').textContent = description;
    $('confirm-input').value = ''; $('confirm-input').placeholder = expected;
    $('confirm-input').setCustomValidity('');
    $('confirm-input').oninput = () => $('confirm-input').setCustomValidity($('confirm-input').value === expected ? '' : 'اكتب التأكيد كما هو معروض.');
    $('confirm-input').setCustomValidity('اكتب التأكيد كما هو معروض.');
    $('confirm-dialog').returnValue = '';
    $('confirm-dialog').onclose = () => resolve($('confirm-dialog').returnValue === 'confirm' && $('confirm-input').value === expected);
    $('confirm-dialog').showModal();
  });
}
$('login-form').onsubmit = e => { e.preventDefault(); action(async () => { const r = await api('login', {password: $('admin-password').value}); $('admin-password').value = ''; csrf = r.csrf; $('notice').hidden = true; await dashboard(); }); };
$('logout').onclick = () => action(async () => { await api('logout', {}); location.reload(); });
$('domain').onchange = () => action(loadEmails);
$('refresh').onclick = () => action(loadEmails);
$('create-form').onsubmit = e => { e.preventDefault(); action(async () => { await api('emails/create', {domain: $('domain').value, user: $('email-user').value, password: $('email-password').value}); $('email-password').value = ''; $('email-user').value = ''; notice('تم إنشاء حساب البريد.'); await loadEmails(); }); };
function tab(section) { for (const name of ['mail', 'bulk', 'delete', 'cleanup', 'retention']) { $(`${name}-section`).hidden = name !== section; $(`${name}-tab`).classList.toggle('active', name === section); } }
$('mail-tab').onclick = () => tab('mail'); $('cleanup-tab').onclick = () => tab('cleanup');
async function loadRetention() {
  const data = await api('retention');
  $('retention-list').replaceChildren();
  if (data.mode === 'demo') { const p = document.createElement('p'); p.textContent = 'الوضع التجريبي: لا توجد مراقبة دخول أو عمليات حذف تلقائي.'; $('retention-list').append(p); return; }
  for (const account of data.accounts) {
    const row = document.createElement('div'); row.className = 'email-row';
    const address = document.createElement('span'); address.className = 'address'; address.textContent = account.email;
    const expiry = document.createElement('span');
    expiry.textContent = account.error || (account.expires_at ? `موعد الحذف: ${new Date(account.expires_at * 1000).toLocaleString('ar-EG')}` : 'في انتظار أول دخول مرصود');
    row.append(address, expiry); $('retention-list').append(row);
  }
  for (const email of data.pending) { const p = document.createElement('p'); p.textContent = `حذف غير مكتمل يحتاج متابعة: ${email}`; $('retention-list').append(p); }
}
$('retention-tab').onclick = () => { tab('retention'); action(loadRetention); };
$('retention-refresh').onclick = () => action(loadRetention);
$('category').onchange = () => { plan = null; $('preview-result').hidden = true; };
$('preview').onclick = () => action(async () => {
  plan = null; $('preview-result').hidden = true;
  plan = await api('cleanup/preview', {category: $('category').value});
  $('preview-summary').textContent = `${plan.files.length} ملف · ${bytes(plan.bytes)} قابلة للتنظيف`;
  $('preview-files').replaceChildren(...plan.files.map(f => { const li = document.createElement('li'); li.textContent = `${f.directory ? f.directory + '/' : ''}${f.name} — ${bytes(f.bytes)}`; return li; }));
  $('preview-result').hidden = false; $('execute').hidden = !plan.files.length;
  if (!plan.available) notice('المجلد غير موجود على السيرفر؛ لا توجد ملفات للتنظيف.');
});
$('execute').onclick = async () => {
  if (!plan || !await confirmText('تنفيذ التنظيف؟', 'سيتم حذف الملفات المعروضة نهائيًا. اكتب «حذف» للتأكيد.', 'حذف')) return;
  action(async () => { const r = await api('cleanup/execute', {token: plan.token, confirmation: 'حذف'}); plan = null; $('preview-result').hidden = true; notice(`تم حذف ${r.deleted} ملف (${bytes(r.bytes)}). تم تخطي ${r.skipped} ملف اتغير أو تعذر حذفه.`); await disk(); });
};
action(async () => { const s = await api('session'); csrf = s.csrf; if (s.authenticated) await dashboard(); else showLogin(); });

$('previous-page').onclick = () => { pageIndex--; renderAccounts(); };
$('next-page').onclick = () => { pageIndex++; renderAccounts(); };
async function loadJobs() {
  const result = await api('jobs');
  $('jobs-list').replaceChildren();
  const names = {queued: 'في الانتظار', running: 'قيد التنفيذ', done: 'اكتملت', paused: 'متوقفة للمراجعة', cancelled: 'أُلغيت'};
  for (const job of result.jobs) {
    const row = document.createElement('div'); row.className = 'job';
    const title = document.createElement('h3');
    const counts = job.counts; const total = Object.values(counts).reduce((a, b) => a + b, 0);
    title.textContent = `${job.kind === 'create' ? 'إنشاء' : 'حذف'} · ${names[job.status] || job.status} · ${counts.done || 0} / ${total}`;
    row.append(title);
    for (const error of job.errors) { const p = document.createElement('p'); p.textContent = `${error.email}: ${error.error}`; row.append(p); }
    if (!['done', 'cancelled'].includes(job.status)) {
      const cancel = document.createElement('button'); cancel.textContent = 'إلغاء المتبقي';
      cancel.onclick = () => action(async () => { await api('jobs/cancel', {job: job.id}); await loadJobs(); notice('تم إلغاء الانتظار؛ الحساب الجاري تنفيذه قد يكتمل.'); }); row.append(cancel);
    }
    $('jobs-list').append(row);
  }
}
$('bulk-tab').onclick = () => { tab('bulk'); action(loadJobs); };
$('jobs-refresh').onclick = () => action(loadJobs);
let jobsLoading = false;
setInterval(async () => { if (!document.hidden && !$('bulk-section').hidden && !$('dashboard').hidden && !busy && !jobsLoading) { jobsLoading = true; try { await loadJobs(); } catch (e) { notice(e.message, true); } finally { jobsLoading = false; } } }, 4000);
for (const id of ['bulk-domain', 'bulk-count', 'bulk-prefix', 'bulk-public']) $(id).addEventListener('change', () => { createRequestId = null; });
$('bulk-form').onsubmit = async event => {
  event.preventDefault();
  const isPublic = $('bulk-public').checked;
  if (isPublic && !await confirmText('إنشاء صناديق عامة؟', 'أي شخص يعرف العنوان يستطيع قراءة رسائله. اكتب «صناديق عامة» للتأكيد.', 'صناديق عامة')) return;
  action(async () => {
    createRequestId ||= crypto.randomUUID();
    await api('bulk/create', {domain: $('bulk-domain').value, count: Number($('bulk-count').value), prefix: $('bulk-prefix').value, public: isPublic, confirmation: isPublic ? 'صناديق عامة' : '', request_id: createRequestId});
    createRequestId = null; notice('تم تسجيل الدفعة. الحسابات الناجحة وكلمات مرورها تظهر في حسابات البريد بعد تحديثها.'); await loadJobs();
  });
};
function invalidateDelete() { deletePlan = null; $('delete-plan').hidden = true; }
async function loadDeleteAccounts() {
  invalidateDelete(); $('delete-list').replaceChildren();
  const result = await api(`emails?domain=${encodeURIComponent($('delete-domain').value)}`);
  for (const [index, email] of result.emails.slice().sort().entries()) {
    const label = document.createElement('label'); label.className = 'check-label';
    const check = document.createElement('input'); check.type = 'checkbox'; check.value = email; check.onchange = invalidateDelete;
    const text = document.createElement('span'); text.textContent = `#${index + 1} ${email}`; text.dir = 'ltr'; label.append(check, text); $('delete-list').append(label);
  }
}
$('delete-tab').onclick = () => { tab('delete'); action(loadDeleteAccounts); };
$('delete-load').onclick = () => action(loadDeleteAccounts);
$('delete-domain').onchange = () => action(loadDeleteAccounts);
$('delete-count').oninput = invalidateDelete;
$('delete-select-all').onclick = () => { invalidateDelete(); const checks = [...$('delete-list').querySelectorAll('input')]; const selected = checks.some(c => !c.checked); checks.forEach(c => c.checked = selected); };
$('delete-preview').onclick = () => action(async () => {
  invalidateDelete();
  deletePlan = await api('bulk/delete/preview', {domain: $('delete-domain').value, count: Number($('delete-count').value), emails: [...$('delete-list').querySelectorAll('input:checked')].map(c => c.value)});
  $('delete-summary').textContent = `سيتم حذف ${deletePlan.emails.length} حساب ورسائلهم نهائيًا`;
  $('delete-addresses').replaceChildren(...deletePlan.emails.map(email => { const li = document.createElement('li'); li.textContent = email; return li; })); $('delete-plan').hidden = false;
});
$('delete-execute').onclick = async () => {
  if (!deletePlan || !await confirmText('تأكيد حذف المجموعة', 'راجع القائمة؛ الحذف نهائي للحسابات ورسائلها. اكتب العبارة المعروضة للتأكيد.', deletePlan.confirmation)) return;
  action(async () => { await api('bulk/delete/execute', {token: deletePlan.token, confirmation: deletePlan.confirmation}); invalidateDelete(); tab('bulk'); await loadJobs(); notice('تم تسجيل دفعة الحذف. تابع النتيجة هنا.'); });
};
