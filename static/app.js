let csrf = '', statusData = null, plan = null, busy = false;
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
  const result = await api(`emails?domain=${encodeURIComponent($('domain').value)}`);
  $('email-count').textContent = result.emails.length;
  if (!result.emails.length) { const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = 'مفيش حسابات بريد على الدومين ده لسه.'; $('email-list').append(empty); }
  for (const email of result.emails) {
    const row = document.createElement('div'); row.className = 'email-row';
    const name = document.createElement('span'); name.className = 'address'; name.textContent = email;
    const button = document.createElement('button'); button.className = 'danger'; button.textContent = 'حذف الحساب';
    button.onclick = async () => {
      const confirmed = await confirmText('حذف حساب البريد؟', 'الحذف نهائي وقد يحذف رسائل الحساب. اكتب عنوان البريد كاملًا للتأكيد:', email);
      if (confirmed) await action(async () => { await api('emails/delete', {email, confirmation: email}); notice('تم حذف الحساب.'); await loadEmails(); });
    };
    row.append(name, button); $('email-list').append(row);
  }
}
async function dashboard() {
  $('login').hidden = true; $('dashboard').hidden = false; $('logout').hidden = false;
  await disk();
  $('mode').textContent = statusData.mode === 'demo' ? 'وضع تجريبي · بدون اتصال بسيرفر' : 'الوضع الفعلي · CyberPanel';
  $('domain').replaceChildren(...statusData.domains.map(d => new Option(d, d)));
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
function tab(mail) { $('mail-section').hidden = !mail; $('cleanup-section').hidden = mail; $('mail-tab').classList.toggle('active', mail); $('cleanup-tab').classList.toggle('active', !mail); }
$('mail-tab').onclick = () => tab(true); $('cleanup-tab').onclick = () => tab(false);
$('category').onchange = () => { plan = null; $('preview-result').hidden = true; };
$('preview').onclick = () => action(async () => {
  plan = null; $('preview-result').hidden = true;
  plan = await api('cleanup/preview', {category: $('category').value});
  $('preview-summary').textContent = `${plan.files.length} ملف · ${bytes(plan.bytes)} قابلة للتنظيف`;
  $('preview-files').replaceChildren(...plan.files.map(f => { const li = document.createElement('li'); li.textContent = `${f.name} — ${bytes(f.bytes)}`; return li; }));
  $('preview-result').hidden = false; $('execute').hidden = !plan.files.length;
  if (!plan.available) notice('المجلد غير موجود على السيرفر؛ لا توجد ملفات للتنظيف.');
});
$('execute').onclick = async () => {
  if (!plan || !await confirmText('تنفيذ التنظيف؟', 'سيتم حذف الملفات المعروضة نهائيًا. اكتب «حذف» للتأكيد.', 'حذف')) return;
  action(async () => { const r = await api('cleanup/execute', {token: plan.token, confirmation: 'حذف'}); plan = null; $('preview-result').hidden = true; notice(`تم حذف ${r.deleted} ملف (${bytes(r.bytes)}). تم تخطي ${r.skipped} ملف اتغير أو تعذر حذفه.`); await disk(); });
};
action(async () => { const s = await api('session'); csrf = s.csrf; if (s.authenticated) await dashboard(); else showLogin(); });
