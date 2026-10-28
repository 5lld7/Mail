import ssl
import unittest
from unittest.mock import patch

from inbox_reader import read_messages


class InboxTests(unittest.TestCase):
    def test_tls_readonly_peek_and_html_text_extraction(self):
        raw = b'From: sender@example.com\r\nSubject: A test\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<h1>Hello</h1><img src="https://external.test/pixel"><script>bad()</script>'
        with patch('inbox_reader.imaplib.IMAP4_SSL') as factory:
            client = factory.return_value.__enter__.return_value
            client.select.return_value = ('OK', [b'1'])
            client.uid.side_effect = [('OK', [b'42']), ('OK', [(b'42', raw)])]
            result = read_messages('public@example.com', 'private-password')
            context = factory.call_args.kwargs['ssl_context']
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            client.select.assert_called_once_with('INBOX', readonly=True)
            self.assertIn('BODY.PEEK[]<0.65536>', client.uid.call_args.args[-1])
            self.assertEqual(result[0]['subject'], 'A test')
            self.assertIn('Hello', result[0]['text'])
            self.assertNotIn('<script>', result[0]['text'])
            self.assertNotIn('external.test', result[0]['text'])
            self.assertNotIn('private-password', str(result))

    def test_fetches_only_ten_most_recent_uids(self):
        with patch('inbox_reader.imaplib.IMAP4_SSL') as factory:
            client = factory.return_value.__enter__.return_value
            client.select.return_value = ('OK', [b'50'])
            client.uid.side_effect = [('OK', [b' '.join(str(n).encode() for n in range(1, 51))])] + [('OK', [(b'x', b'Subject: test\r\n\r\nbody')])] * 10
            result = read_messages('a@example.com', 'secret')
            self.assertEqual(len(result), 10)
            calls = client.uid.call_args_list[1:]
            self.assertEqual(calls[0].args[1], b'50')
            self.assertEqual(calls[-1].args[1], b'41')


if __name__ == '__main__':
    unittest.main()
