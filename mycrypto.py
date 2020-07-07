#!/usr/bin/env python3

# general imports --------------------------------------------------------- {{{1
import os
import argparse
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from subprocess import Popen, PIPE


# classes ----------------------------------------------------------------- {{{1
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


# functions --------------------------------------------------------------- {{{1
def generate_rsa_key_pair(keyname='generated_rsa', password=None):
    '''
    Generates RSA public/private key pair.
    idea from: https://stackoverflow.com/questions/2466401/how-to-generate-ssh-key-pairs-with-python
    In:
        keyname:  generated RSA key pair name
    Optional:
        password: optional password for the RSA key
    Out:
        RSA key pair
    '''
    print('[+] generating RSA key pair.')
    if keyname is None:
        path = os.path.join(os.getcwd(), 'generated_rsa')
    else:
        path = keyname

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


def encrypt(string_to_encrypt, public_key, encrypted_file='password.bin'):
    '''
    ENCRYPTS a string using RSA - AES key combination. First an AES session key
    is generated, then it is used to encrypt the string_to_encrypt. Aftwerwards
    the AES session key is encrypted using the RSA public key and the encrypted
    AES key is stored together with the encrypted string_to_encrypt in a file.
    This has the advantage of encrypting strings too short for a RSA encryption
    (e.g. passwords).

    WARNING: Does not work if RSA key has password.

    In:
        string_to_encrypt: string to be encrypted
        public_key:        file with RSA public key
    Optional:
        encrypted_file:    filename where to store the ecrypted string
                           (DEFAULT = password.bin)'
    Out:
        file with the encrypted string
    '''

    assert(type(string_to_encrypt) == str), 'string_to_encrypt ({0}) must be a string.'.format(string_to_encrypt)
    assert(string_to_encrypt != ''), 'string_to_encrypt cannot be a nullstring'
    assert(os.path.isfile(public_key)), 'public_key file ({0}) does not exist'.format(public_key)

    recipient_key = RSA.importKey(open(public_key, 'r').read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    # EAX mode is used to allow detection of unauthoriyed modifications
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(string_to_encrypt.encode('utf-8'))

    with open(encrypted_file, 'wb') as file_out:
        [file_out.write(x) for x in (enc_session_key,
                                     cipher_aes.nonce,
                                     tag,
                                     ciphertext)]

    return encrypted_file


def decrypt(string_to_decrypt, private_key):
    '''
    DECRYPTS a string ENCRYPTED using RSA - AES key combination. RSA encrypted
    key is extracted from the string_to_decrypt, decrypted using RSA private
    key and the ewsulting AES session key is used to decrypt the encrypted
    string stored at the end of the string_to_decrypt file.

    WARNING: Does not work if RSA key has password.

    In:
        string_to_decrypt: file with (RSA encrypted AES session key, AES
                           session key NONCE, TAG, encrypted text)
        private_key:       RSA private key filename
    Out:
        decrypted string if everything works, AssertionError if not
    '''

    assert(os.path.isfile(string_to_decrypt)), 'string_to_decrypt {0} is not a file.'.format(string_to_decrypt)
    assert(os.path.isfile(private_key)), 'private_key file ({0}) does not exist.'.format(private_key)

    key = RSA.importKey(open(private_key, 'r').read())

    with open(string_to_decrypt, 'rb') as file_in:
        enc_session_key, nonce, tag, ciphertext = [file_in.read(x) for x in (key.size_in_bytes(), 16, 16, -1)]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted_string = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_string.decode('utf-8')


def test_encryption(private_key=None, public_key=None, test_string='This is a test string'):
    '''
    Tests if encrypt() and decrypt() functions work both ways. First the
    test_string is ENCRYPTED, then the encrypted string is DECRYPTED and the
    result is checked.

    In:
        private_key: RSA private key file
        public_key:  RSA public key file
        test_string: String to test the ecryption on
                     (DEFAULT = 'This is a test string')
    Out:
        True if the ENCRYPTION - DECRYPTION works, AssertionError if not.
    '''

    assert(private_key is None), '[-] No private key supplied. Encryption cannot be tested.'
    assert(public_key is None), '[-] No public key supplied. Encryption cannot be tested.'

    print('[+] Private key: {0}'.format(private_key))
    print('[+] Public key: {0}'.format(public_key))

    test_string = 'this is a test string'
    print('test string: {0}'.format(test_string))
    encrypted = encrypt(test_string, public_key, )

    decrypted = decrypt(encrypted, private_key)
    print('decrypted string: {0}'.format(decrypted))

    assert(test_string == decrypted), 'Encryption -> Decryption did not work: {0} != {1}'.format(test_string, decrypted)
    os.remove(encrypted)

    return True


# main entrypoint ----------------------------------------------- {{{1
if __name__ == '__main__':
    pubkey = [f for f in os.listdir() if f.endswith('.pub')]
    if len(pubkey) > 0:
        pubkey = pubkey[0]
        prikey = pubkey.replace('.pub', '')
    else:
        pubkey = None
        prikey = None

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--rsa-public", type=str, action=CheckPath, default=pubkey,
                        help="supply path for rsa public key to decrypt passwords")
    parser.add_argument("-r", "--rsa-private", type=str, action=CheckPath, default=prikey,
                        help="supply path for rsa private key to encrypt passwords")

    parser_group = parser.add_mutually_exclusive_group()
    parser_group.add_argument('-e', '--encrypt', default=False, action='store_true',
                              help='ENCRYPT supplied password')
    parser_group.add_argument('-d', '--decrypt', default=False, action='store_true',
                              help='DECRYPT supplied password *.bin file')

    parser.add_argument('password', type=str, nargs=1,
                        help='password to ENCRYPT or *.bin file to DECRYPT')

    args = parser.parse_args()

    if args.encrypt and args.decrypt:
        sys.exit('[-] Only one option (--encrypt/--decrypt) must be selected. Exiting.')

    elif args.decrypt:
        if not os.path.isfile(args.password[0]):
            sys.exit('[-] PATH to {0} file is invalid. Exiting.'.format(args.password[0]))

        if args.rsa_private is None:
            sys.exit('[-] No private RSA key supplied - cannot decrypt password file. Exiting.')
        elif not os.path.isfile(args.rsa_private):
            sys.exit('[-] Nonexistent private RSA key supplied. Exiting.')

        decrypted_pass = decrypt(args.password[0], args.rsa_private)
        print('[+] Decrypted password: {0}'.format(decrypted_pass))

    elif args.encrypt:
        if os.path.isfile(args.password[0]):
            with open(args.password[0], 'r', encoding='utf-8') as pfile:
                password = pfile.read()
        else:
            password = args.password[0]

        if args.rsa_public is None:
            print('[?] No public RSA key supplied, do you want to generate RSA public/provate key pair? [Y/n]')

            if input().upper() in ('Y', 'YES'):
                prikey, pubkey = generate_rsa_key_pair()
                print('[+] generated: {0}, {1}'.format(prikey, pubkey))
            else:
                sys.exit('[-] No public RSA key supplied - cannot encrypt password (file). Exiting.')

        elif not os.path.isfile(args.rsa_public):
            sys.exit('[-] Nonexistent public RSA key supplied. Exiting.')

        else:
            pubkey = args.rsa_public

        encrypted_pass = encrypt(password, pubkey)
        print('[+] Encrypted password: {0}'.format(encrypted_pass))

    else:
        sys.exit('[-] Either --encrypt or --decrypt option must be selected. Exiting.')
