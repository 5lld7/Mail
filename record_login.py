#!/usr/bin/python3
"""Dovecot postlogin hook; recording failure must not prevent mail access."""
import os
import sys
import syslog

from retention import record_login


if __name__ == '__main__':
    try:
        record_login(os.environ.get('USER', ''))
    except Exception:
        syslog.syslog(syslog.LOG_ERR, 'mail-panel: first-login recording failed; auto-expiry unavailable for this login')
    # Dovecot passes its IMAP/POP3 executable after the postlogin script.
    if len(sys.argv) < 2 or not os.path.isabs(sys.argv[1]):
        sys.exit('Missing Dovecot postlogin executable')
    os.execv(sys.argv[1], sys.argv[1:])
