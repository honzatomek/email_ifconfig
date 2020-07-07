#!/usr/bin/env python3

# general imports ----------------------------------------------- {{{1
import os
import configparser
import argparse
from mycrypto import encrypt, decrypt, generate_rsa_key_pair


# global variables ---------------------------------------------- {{{1
CONFIG = 'mail.ini'
PASSWORD_FILENAME = 'password.bin'


# classes ------------------------------------------------------- {{{1
class InvalidPath(Exception):
    pass


class CheckPath(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(CheckPath, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
#         print('%r %r %r' % (namespace, values, option_string))
        if not isinstance(values, str):
            raise InvalidPath('only one path is allowed')
        if not os.path.isfile(values):
            raise InvalidPath('supplied path is not valid {0}'.format(values))
        print('[+] {0} exists: True'.format(values))
        setattr(namespace, self.dest, values)


# functions ----------------------------------------------------- {{{1
def input_default(prompt, default, to_type=str):
    val = input('    {0} (default: {1}): '.format(prompt, default))
    if val is '':
        val = default
    return to_type(val)


def input_list(prompt, default):
    print('    {0} (default: {1}):'.format(prompt, str(default)))
    vals = []
    val = None
    i = 0
    while True:
        i += 1
        val = input('        Command {0}: '.format(i))
        if len(vals) == 0 and val == '':
            vals = default
            break
        elif val == '':
            break
        else:
            vals.append(val)
    return vals


# main function ------------------------------------------------- {{{1
def edit_ini(private_key=None, public_key=None):
    print('[+] Private key: {0}'.format(private_key))
    print('[+] Public key: {0}'.format(public_key))

    ini = configparser.ConfigParser()
    ini.read(CONFIG)

    for section in ini.sections():
        print(f'[{section}]')
        for key in ini[section].keys():
            if key == 'password':
                # TODO: implement from getpass import getpass method to not show the password
                if os.path.isfile(ini[section][key]):
                    ini[section][key] = encrypt(input_default(key, decrypt(ini[section][key], private_key), str), public_key, PASSWORD_FILENAME)
                else:
                    ini[section][key] = encrypt(input_default(key, 'mysupersecretpaswword', str), public_key, PASSWORD_FILENAME)
            elif key == 'rsa_private':
                if private_key != ini[section][key] and private_key is not None:
                    ini[section][key] = input_default(key, private_key, str)
                else:
                    ini[section][key] = input_default(key, ini[section][key], str)
                private_key = ini[section][key]
            elif key == 'rsa_public':
                if public_key != ini[section][key] and public_key is not None:
                    ini[section][key] = input_default(key, public_key, str)
                else:
                    ini[section][key] = input_default(key, ini[section][key], str)
                public_key = ini[section][key]
            elif key == 'commands':
                ini[section][key] = '\n'.join(input_list(key, ini[section][key].split('\n')))
            else:
                ini[section][key] = input_default(key, ini[section][key], str)

    with open(CONFIG, 'w', encoding='utf-8') as config:
        ini.write(config)

    print('[+] {0} file written.'.format(CONFIG))

def generate_ini(private_key=None, public_key=None):
    print('[+] Private key: {0}'.format(private_key))
    print('[+] Public key: {0}'.format(public_key))

    ini = configparser.ConfigParser()
    print('[+] Input the data for sending e-mail account (password will be encrypted using RSA public key, only gmail was tested):')
    sender = 'SENDER'
    sender_name = input_default('Name', 'My Raspberry Pi4', str)
    sender_email = input_default('E-mail', 'senderemail@gmail.com', str)
    # TODO: implement from getpass import getpass method to not show the password
    sender_pass = encrypt(input_default('Password', 'mysupersecretpassword', str), public_key, PASSWORD_FILENAME)
    sender_port = input_default('Port', '465', str)
    sender_server = input_default('Server', 'smtp.gmail.com', str)
    sender_protocol = input_default('Protocol', 'SSL', str)

    print('[+] Input the data for receiving e-mail account:')
    receiver = 'RECEIVER'
    receiver_name = input_default('Name', 'John Doe', str)
    receiver_email = input_default('E-mail', 'receiver@receiver.com')

    print('[+] Input other general data:')
    subject = input_default('E-mail Subject', 'My Raspberry Pi4 ifconfig', str)
    commands = ['ifconfig', 'iwconfig', 'curl https://ipecho.net/plain', 'netstat -r', 'traceroute 8.8.8.8']
    commands = input_list('Commands to Execute', commands)

    ini['GLOBAL'] = {'sender': sender,
                     'receiver': receiver,
                     'subject': subject,
                     'rsa_private': private_key,
                     'rsa_public': public_key,
                     'commands': '\n'.join(commands)}
    ini[sender] = {'name': f'{sender_name} <{sender_email}>',
                   'username': sender_email,
                   'password': sender_pass,
                   'port': sender_port,
                   'server': sender_server,
                   'protocol': sender_protocol}
    ini[receiver] = {'name': f'{receiver_name} <{receiver_email}>'}

    with open(CONFIG, 'w', encoding='utf-8') as config:
        ini.write(config)

    print('[+] {0} file written.'.format(CONFIG))


# main entrypoint ----------------------------------------------- {{{1
if __name__ == '__main__':
    pubkey = [f for f in os.listdir() if f.endswith('.pub')]
    if len(pubkey) > 0:
        pubkey = pubkey[0]
        prikey = pubkey.replace('.pub', '')
    else:
        pubkey = None
        prikey = None

    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--rsa-public", type=str, action=CheckPath, default=pubkey,
                    help="supply path for rsa public key to decrypt passwords")
    ap.add_argument("-r", "--rsa-private", type=str, action=CheckPath, default=prikey,
                    help="supply path for rsa private key to encrypt passwords")
    ap.add_argument('-e', '--edit', default=False, action='store_true',
                    help='edit existing *.ini file')

    args = ap.parse_args()
    if args.edit:
        edit_ini()
    else:
        if args.rsa_public is None or args.rsa_private is None:
            prikey, pubkey = generate_rsa_key_pair()
        else:
            prikey = os.path.join(os.getcwd(), args.rsa_private)
            pubkey = os.path.join(os.getcwd(), args.rsa_public)
        generate_ini(private_key=prikey, public_key=pubkey)
