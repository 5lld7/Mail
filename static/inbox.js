const input = document.getElementById('inbox-email');
const status = document.getElementById('inbox-status');
const messages = document.getElementById('messages');
let activeEmail = '', loading = false;
input.value = new URLSearchParams(location.search).get('email') || '';
async function load() {
  if (!activeEmail || loading) return;
  loading = true; status.textContent = 'جارٍ تحميل الرسائل…';
  const requested = activeEmail;
  try {
    const response = await fetch('/public-api/messages', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({email: requested})});
    const data = await response.json();
    if (activeEmail !== requested) return;
    if (!response.ok) throw new Error(data.error || 'تعذر تحميل الرسائل.');
    messages.replaceChildren();
    for (const message of data.messages) {
      const card = document.createElement('article'); card.className = 'card message';
      const title = document.createElement('h2'); title.textContent = message.subject;
      const meta = document.createElement('p'); meta.textContent = `${message.sender} · ${message.date}`;
      const body = document.createElement('pre'); body.textContent = message.text;
      card.append(title, meta, body);
      if (message.limited) { const note = document.createElement('p'); note.textContent = 'الرسالة كبيرة؛ المعروض جزء منها.'; card.append(note); }
      messages.append(card);
    }
    status.textContent = data.demo ? 'وضع تجريبي؛ لا يوجد اتصال بصندوق حقيقي.' : `آخر تحديث: ${new Date().toLocaleTimeString('ar-EG')} · ${data.messages.length} رسالة`;
  } catch (error) { messages.replaceChildren(); status.textContent = error.message; }
  finally { loading = false; }
}
document.getElementById('inbox-form').onsubmit = event => { event.preventDefault(); activeEmail = input.value.trim(); messages.replaceChildren(); load(); };
setInterval(() => { if (!document.hidden) load(); }, 15000);
