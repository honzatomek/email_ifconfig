#!/usr/bin/env python3
import os

SERVICE_TEMPLATE = '''[Unit]
Description=e-mail ifconfig Service
After=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory={{cwd}}
ExecStart={{script}}

[Install]
WantedBy=multi-user.target'''


def generate_service():
    cwd = os.getcwd()
    script = cwd + '/email_ifconfig.py'
    template = SERVICE_TEMPLATE.replace('{{cwd}}', cwd).replace('{{script}}', script)
    with open('email_ifconfig.service', 'w', encoding='utf-8') as service:
        service.write(template)

if __name__ == '__main__':
    generate_service()
