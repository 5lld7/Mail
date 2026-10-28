"""Read a bounded number of messages over verified TLS, without marking read."""
import email
import imaplib
import os
import ssl
from email import policy
from html.parser import HTMLParser


class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
    def handle_data(self, data):
        self.text.append(data)


def read_messages(address, password):
    host = os.environ.get('PANEL_IMAP_HOST', 'mail.jxil.org')
    port = int(os.environ.get('PANEL_IMAP_PORT', '993'))
    with imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context(), timeout=12) as client:
        client.login(address, password)
        code, _ = client.select('INBOX', readonly=True)
        if code != 'OK':
            raise ValueError('Cannot open inbox')
        code, found = client.uid('search', None, 'ALL')
        if code != 'OK':
            raise ValueError('Cannot list inbox')
        messages = []
        for uid in reversed(found[0].split()[-10:]):
            code, rows = client.uid('fetch', uid, '(RFC822.SIZE BODY.PEEK[]<0.65536>)')
            if code != 'OK':
                continue
            raw = next((r[1] for r in rows if isinstance(r, tuple) and isinstance(r[1], bytes)), None)
            if raw is None:
                continue
            message = email.message_from_bytes(raw[:65536], policy=policy.default)
            part = message.get_body(preferencelist=('plain', 'html'))
            content = part.get_content() if part is not None else ''
            if not isinstance(content, str):
                content = ''
            if part is not None and part.get_content_type() == 'text/html':
                parser = TextOnly()
                parser.feed(content)
                content = '\n'.join(parser.text)
            messages.append({'id': uid.decode(), 'subject': str(message.get('Subject', 'بدون عنوان')),
                             'sender': str(message.get('From', '')), 'date': str(message.get('Date', '')),
                             'text': content[:50000], 'limited': len(raw) >= 65536})
        return messages
