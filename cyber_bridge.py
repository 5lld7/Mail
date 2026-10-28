"""Executed only by CyberPanel's Python; passwords arrive over stdin, never argv."""
import json
import os
import sys


def main():
    data = json.load(sys.stdin)
    sys.path.insert(0, '/usr/local/CyberCP')
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CyberCP.settings')
    import django
    django.setup()
    from plogical.mailUtilities import mailUtilities

    action = data['action']
    if action == 'inventory':
        from mailServer.models import EUsers
        result = list(EUsers.objects.order_by('email').values_list('email', flat=True))
    elif action == 'list':
        from mailServer.models import EUsers
        result = list(EUsers.objects.filter(emailOwner_id=data['domain']).order_by('email').values_list('email', flat=True))
    elif action == 'create':
        status = mailUtilities.createEmailAccount(data['domain'], data['user'], data['password'])
        result = {'ok': status[0] == 1}
    elif action == 'delete':
        status = mailUtilities.deleteEmailAccount(data['email'])
        result = {'ok': status[0] == 1}
    else:
        raise ValueError('Unsupported action')
    print('MAIL_PANEL_RESULT=' + json.dumps(result))


if __name__ == '__main__':
    main()
