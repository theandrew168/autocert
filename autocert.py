"""
https://tools.ietf.org/html/rfc8555
https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md

https://github.com/golang/crypto/tree/master/acme/autocert
https://github.com/farrepa/django-autocert/tree/develop/autocert
https://github.com/diafygi/acme-tiny

https://docs.python.org/3/library/socket.html
https://docs.python.org/3/library/ssl.html


The game plan:
--------------

cache dir exists (appdirs)?
if exists:
    import
    check renew now
    schedule renew
else:
    obtain
    schedule renew

kick off renew thread (renew at 30 day mark +/- 30 mins jitter)
keep track of the SSLContext used to create the SSLSocket
when new cert is acquired:
    update the cache (appdirs)
    call context.load_cert_chain()

new clients from accept() should now get the new stuff
old ones will still have the "old" cert but that's fine (still valid)
"""

import base64
import json
import os
import socket
import ssl

import appdirs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import requests

#LETS_ENCRYPT_ACME_URL = 'https://acme-v02.api.letsencrypt.org/directory'
LETS_ENCRYPT_ACME_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'


class AutocertError(Exception):
    pass


def base64_encode(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace('=', '')


def do(s80, s443, *domains, accept_tos=False):
    # ensure args are valid
    if not accept_tos:
        raise AutocertError("CA's Terms of Service must be accepted")
    if not isinstance(s80, socket.socket):
        raise AutocertError('Socket s80 must be a socket')
    if not isinstance(s443, socket.socket):
        raise AutocertError('Socket s443 must be a socket')
#    if s80.getsockname()[1] != 80:
#        raise AutocertError('Socket s80 must be listening on port 80')
#    if s443.getsockname()[1] != 443:
#        raise AutocertError('Socket s443 must be listening on port 443')

    # ensure TLS cert cache dir exists
    cache_dir = appdirs.user_cache_dir('python-autocert', 'python-autocert')
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)

    # grab the ACME directory
    directory = requests.get(LETS_ENCRYPT_ACME_URL)
    directory = directory.json()
    from pprint import pprint
    pprint(directory)

    # generate an EC private key
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    print(private_bytes.decode())

    # generate an EC public key (from the private key)
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    x = numbers.x
    x = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
    x = base64_encode(x)
    print(x)

    y = numbers.y
    y = y.to_bytes((y.bit_length() + 7) // 8, byteorder='big')
    y = base64_encode(y)
    print(y)

    # check if account already exists
    acct_path = os.path.join(cache_dir, 'acme_account')
    if not os.path.exists(acct_path):
        # grab a fresh nonce
        resp = requests.head(directory['newNonce'])
        nonce = resp.headers['Replay-Nonce']

        # https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-06#appendix-A.2
        protected = {
            'alg': 'ES256',
            'jwk': {
                'kty': 'EC',
                'crv': 'P-256',
                'x': x,
                'y': y,
            },
            'nonce': nonce,
            'url': directory['newAccount'],
        }
        protected = json.dumps(protected, separators=(',', ':'), sort_keys=True)
        protected = base64_encode(protected.encode())
        print(protected)

        payload = {
            'termsOfServiceAgreed': accept_tos,
        }
        payload = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        payload = base64_encode(payload.encode())
        print(payload)

        # https://community.letsencrypt.org/t/parse-error-reading-jws/137654/13
        signature = private_key.sign('.'.join([protected, payload]).encode(), ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(signature)
        r = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
        s = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
        print(len(r), r)
        print(len(s), s)
        signature = base64_encode(r + s)
        print(signature)

        headers = {
            'Content-Type': 'application/jose+json',
        }

        data = {
            'protected': protected,
            'payload': payload,
            'signature': signature,
        }
        data = json.dumps(data, separators=(',', ':'))
        print(data)

        #resp = requests.post(directory['newAccount'], headers=headers, data=data)
        #print(resp)
        #print(resp.headers)
        #print(resp.json())
    else:
        print('account already exists:')
        with open(acct_path) as f:
            acct = f.read()
            print(acct)


if __name__ == '__main__':
    s80 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s80.bind(('0.0.0.0', 8080))
    s80.listen()

    s443 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s443.bind(('0.0.0.0', 8443))
    s443.listen()

    do(s80, s443, 'foobar.org', 'www.foobar.org', accept_tos=True)
