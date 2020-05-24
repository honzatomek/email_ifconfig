#!/usr/bin/env python3

# general imports ----------------------------------------------- {{{1
import os
import configparser
import argparse
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from subprocess import Popen, PIPE


# global variables ---------------------------------------------- {{{1
# RSA = None
CONFIG = 'mail.ini'


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
def generate_rsa_key_pair(password=None):
    '''
    idea from: https://stackoverflow.com/questions/2466401/how-to-generate-ssh-key-pairs-with-python
    '''
    print('[+] generating RSA key pair.')
    path = os.path.join(os.getcwd(), 'email_ifconfig_rsa')

    if os.path.isfile(path):
        print('[+] removing existing file: {0}'.format(path))
        os.remove(path)

    if os.path.isfile(path + '.pub'):
        print('[+] removing existing file: {0}'.format(path + '.pub'))
        os.remove(path + '.pub')

    cmd = ['ssh-keygen', '-m', 'PEM', '-t', 'rsa', '-f', path]
    if password:
        cmd.append('-P')
        cmd.append(password)

    p = Popen(cmd, stdout=PIPE)
    p.wait()
    res, err = p.communicate()

    if err:
        raise Exception(err)

    if res:
        cert_content = res.decode('utf-8')
        print('[+] Certificate: {0}'.format(cert_content))

    return path, path + '.pub'


def encrypt(string_to_encrypt, public_key):
    key = RSA.importKey(open(public_key, 'r').read())
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(string_to_encrypt.encode('utf-8'))


def decrypt(string_to_decrypt, private_key):
    key = RSA.importKey(open(private_key, 'r').read())
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(string_to_decrypt).decode('utf-8')


def test_encryption(private_key=None, public_key=None):
    print('[+] Private key: {0}'.format(private_key))
    print('[+] Public key: {0}'.format(public_key))

    test_string = 'this is a test string'
    print('test string: {0}'.format(test_string))
    encrypted = encrypt(test_string, public_key)
    print('encrypted string: {0}'.format(encrypted))
    decrypted = decrypt(encrypted, private_key)
    print('decrypted string: {0}'.format(decrypted))


def input_default(prompt, default, to_type=str):
    val = input('{0} (default: {1}): '.format(prompt, default))
    if val is '':
        val = default
    return to_type(val)


def input_list(prompt, default):
    print('{0} (default: {1}):'.format(prompt, str(default)))
    vals = []
    val = None
    i = 0
    while True:
        i += 1
        val = input('Command {0}: '.format(i))
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

    default = ini['DEFAULT']
    sender = ini['DEFAULT']['sender']
    for key in ini[sender].keys():
        if key == 'password':
            ini[sender][key] = encrypt(input_default(key, decrypt(ini[sender][key].strip(), private_key), str), public_key)
        else:
            ini[sender][key] = input_default(key, ini[sender][key], str)

def generate_ini(private_key=None, public_key=None):
    print('[+] Private key: {0}'.format(private_key))
    print('[+] Public key: {0}'.format(public_key))

    ini = configparser.ConfigParser()
    print('[+] Input the data for sending e-mail account (password will be encrypted using RSA public key, only gmail was tested):')
    sender = 'SENDER'
    sender_name = input_default('Name', 'My Raspberry Pi4', str)
    sender_email = input_default('E-mail', 'senderemail@gmail.com', str)
    sender_pass = encrypt(input_default('Password', 'mysupersecretpassword', str), public_key)
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

    ini['DEFAULT'] = {'sender': sender,
                      'receiver': receiver,
                      'subject': subject,
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
    if args.rsa_public is None or args.rsa_private is None:
        prikey, pubkey = generate_rsa_key_pair()
    else:
        prikey = os.path.join(os.getcwd(), args.rsa_private)
        pubkey = os.path.join(os.getcwd(), args.rsa_public)
    if args.edit:
        edit_ini(private_key=prikey, public_key=pubkey)
    else:
        generate_ini(private_key=prikey, public_key=pubkey)
