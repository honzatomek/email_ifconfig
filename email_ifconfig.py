#!/usr/bin/env python3

# general imports ---------------------------------------------------------------->
import os
import sys
import subprocess
import datetime
import re
import configparser
import smtplib
import socket
from time import sleep
from email.message import EmailMessage

from generate_ini import decrypt

# Global variables --------------------------------------------------------------->
CONFIG = './mail.ini'
MAX_TIMEOUT = 32


def connected(host='8.8.8.8', port=53, timeout=3):
    '''
    Host: 8.8.8.8 (google-public-dns-a.google.com)
    OpenPort: 53/TCP
    Service: domain (DNS/TCP)
    '''
    try:
        print('[+] Checking internet connection.')
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        print('[+] Connected to internet.')
        return True
    except Exception as ex:
        # print(ex.message)
        print ('[-] Not connected to internet..')
        return False


def get_command(command='ifconfig'):
    '''
    Function to get a specific bash command output. Default is ifconfig.
    '''
    print('[+] Getting {0} output.'.format(command))
    try:
        output = str(subprocess.check_output(command).decode('ascii')).strip()
    except Exception as e:
        print(e)
        output = None
    return output


def compose_message(commands=['ifconfig']):
    '''
    Function to compose the body of the e-mail message.
    '''
    message = ''
    header_len = 40
    for command in commands:
        tmp = get_command(command.split(' '))
        if not tmp is None:
            header = '[+] Output of command: {0} '.format(command)
            frame = '=' * header_len
            message += frame + '\n' + header + '\n' + frame + '\n' + tmp + '\n\n'
    return message


class config():
    '''
    Class wrapper to automate configparser.
    '''
    def __init__(self, ini=CONFIG):
        '''
        Constructor, ini = path to .ini file to be parsed
        '''
        self.__ini = configparser.ConfigParser()
        self.__ini.read(ini)

    def get_section(self, section='GLOBAL'):
        '''
        Function to read whole section from *.ini file and return it as a dicitionary.
        If the section is not present, return None.
        '''
        try:
            data = self.__ini[section]
        except Exception as e:
            print(e)
            data = None
        return data

    def get_config(self, section='GLOBAL', key='email_to'):
        '''
        Function to get a specific key from a specific section of *.ini file.
        '''
        try:
            ret_val = self.__ini[section][key]
        except Exception as e:
            print(e)
            ret_val = None
        return ret_val


def main():
    '''
    Main body of the script
    '''
    # check if connected to internet
    print('[+] Script {0} starting.'.format(__file__))
    timeout = 1
    while not connected():
        print('[i] Waiting {0} secs..'.format(timeout))
        sleep(timeout)
        timeout = min(timeout * 2, MAX_TIMEOUT)

    # compose an e-mail message
    print('[+] Composing message.')
    ini = config(CONFIG)

    sender = ini.get_section(ini.get_config('GLOBAL', 'sender'))
    receiver = ini.get_section(ini.get_config('GLOBAL', 'receiver'))

    msg = EmailMessage()
    msg.set_content(compose_message(ini.get_config('GLOBAL', 'commands').split('\n')))
    msg['Subject'] = ini.get_config('GLOBAL', 'subject')
    msg['From'] = sender['name']
    msg['To'] = receiver['name']

    # Send the message via our own SMTP server.
    print('[+] Sending e-mail...')
    with smtplib.SMTP_SSL(sender['server'], int(sender['port'])) as s:
        s.login(sender['username'], decrypt(sender['password'], ini.get_config('GLOBAL', 'rsa_private')))
        s.send_message(msg)
        print('[+] E-mail sent to {0}.'.format(receiver['name']))


if __name__ == '__main__':
    '''
    Main entrypoint of the script.
    '''
    main()

