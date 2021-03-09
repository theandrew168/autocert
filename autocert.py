"""
https://tools.ietf.org/html/rfc8555
https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md

https://github.com/golang/crypto/tree/master/acme/autocert
https://github.com/farrepa/django-autocert/tree/develop/autocert
https://github.com/diafygi/acme-tiny

https://docs.python.org/3/library/socket.html
https://docs.python.org/3/library/ssl.html

https://github.com/dehydrated-io/dehydrated/blob/master/docs/tls-alpn.md
https://fossies.org/linux/ansible/lib/ansible/modules/crypto/acme/acme_challenge_cert_helper.py
https://sites.lafayette.edu/fultonc/2019/02/03/using-tls-alpn-01-on-a-raspberry-pi/


The game plan:
--------------
if not exists(cache_dir):
    create cache_dir

fetch directory

if exists(acct):
    load pkey from cache
    lookup acct by pkey
else:
    generate pkey
    save pkey to cache
    create acct

for cert in certs:
    if not exists(cert):
        order + challenge + poll cert
        save cert to cache
    else:
        load cert from cache
        check renew now

    schedule renew (30 days remaining +/- 30 mins jitter)


renew
-----
if remaining > 30 days:
    sleep(remaining - 30 days)
else:
    order + challenge + poll cert
    save cert to cache
    call s.context.load_cert_chain()

keep track of the SSLContext (or just the SSLSocket)
new clients from accept() should now get the new stuff
old ones will still have the "old" cert but that's fine (still valid)
"""

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import socket
import ssl
from threading import Thread

import appdirs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
import requests

#LETS_ENCRYPT_ACME_URL = 'https://acme-v02.api.letsencrypt.org/directory'
LETS_ENCRYPT_ACME_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'


# TODO: can this be made better / simpler?
class HTTPRedirectHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        return

    def redirect(self):
        self.send_response(301)
        self.send_header('Location', 'https://' + self.headers.get('Host') + self.path)
        self.end_headers()

    do_GET = redirect
    do_HEAD = redirect
    do_POST = redirect
    do_PUT = redirect
    do_DELETE = redirect
    do_TRACE = redirect
    do_OPTIONS = redirect
    do_CONNECT = redirect
    do_PATCH = redirect


class HTTPRedirectServer(HTTPServer):

    def __init__(self, s80):
        super().__init__(s80.getsockname(), HTTPRedirectHandler, bind_and_activate=False)
        self.socket = s80
        self.bg_server = Thread(target=self.serve_forever, daemon=True)

    def start(self):
        self.bg_server.start()


class AutocertError(Exception):
    pass


def base64_encode(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace('=', '')


def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')


class ACMEClient:

    def __init__(self, accept_tos=False, directory_url=LETS_ENCRYPT_ACME_URL):
        if not accept_tos:
            raise AutocertError("CA's Terms of Service must be accepted")

        self.accept_tos = accept_tos
        self.directory_url = directory_url

        # grab current directory and initial nonce
        self.directory = requests.get(self.directory_url).json()
        self.nonce = requests.head(self.directory['newNonce']).headers['Replay-Nonce']

        # ensure autocert cache dir exists
        cache_dir = appdirs.user_cache_dir('python-autocert', 'python-autocert')
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

        # check if account already exists
        acct_path = os.path.join(cache_dir, 'acme_account')
        if os.path.exists(acct_path):
            # load pkey from cache
            with open(acct_path, 'rb') as f:
                pem = f.read()
            self.private_key = serialization.load_pem_private_key(pem, password=None)
        else:
            # generate a new pkey
            self.private_key = ec.generate_private_key(ec.SECP256R1())
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            # save pkey to cache
            with open(acct_path, 'wb') as f:
                f.write(pem)

        # setup the other key info
        self.public_key = self.private_key.public_key()
        self.x = int_to_bytes(self.public_key.public_numbers().x)
        self.y = int_to_bytes(self.public_key.public_numbers().y)
        self.account_key = {
            'crv': 'P-256',
            'kty': 'EC',
            'x': base64_encode(self.x),
            'y': base64_encode(self.y),
        }

        # calculate key thumbprint (for authz)
        akey_json = json.dumps(self.account_key, separators=(',', ':'), sort_keys=True)
        self.thumbprint = base64_encode(hashlib.sha256(akey_json.encode()).digest())

        # create or find the account URL
        self.account_url = None
        resp = self._create_or_find_account()
        self.account_url = resp.headers['Location']

    def _cmd(self, url, payload):
        # https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-06#appendix-A.2
        protected = {
            'alg': 'ES256',
            'nonce': self.nonce,
            'url': url,
        }

        # set jwk / kid based on account_url
        if self.account_url is None:
            protected['jwk'] = self.account_key
        else:
            protected['kid'] = self.account_url

        protected = json.dumps(protected, separators=(',', ':'), sort_keys=True)
        protected = base64_encode(protected.encode())

        if payload is None:
            payload = ''
        else:
            payload = json.dumps(payload, separators=(',', ':'), sort_keys=True)
            payload = base64_encode(payload.encode())

        # https://community.letsencrypt.org/t/parse-error-reading-jws/137654/13
        signature = self.private_key.sign(
            '.'.join([protected, payload]).encode(),
            ec.ECDSA(hashes.SHA256())
        )
        r, s = utils.decode_dss_signature(signature)
        signature = base64_encode(int_to_bytes(r) + int_to_bytes(s))

        headers = {
            'Content-Type': 'application/jose+json',
        }

        data = {
            'protected': protected,
            'payload': payload,
            'signature': signature,
        }
        data = json.dumps(data, separators=(',', ':'))

        # create account
        resp = requests.post(url, headers=headers, data=data)
        if resp.status_code not in [200, 201]:
            raise AutocertError('Command failed: {}'.format(resp.json()))

        # update nonce
        self.nonce = resp.headers['Replay-Nonce']

        return resp

    def _create_or_find_account(self):
        url = self.directory['newAccount']
        payload = {
            'termsOfServiceAgreed': self.accept_tos,
        }

        return self._cmd(url, payload)

    def new_order(self, domains):
        url = self.directory['newOrder']
        payload = {
            'identifiers': [{'type': 'dns', 'value': domain} for domain in domains],
        }

        return self._cmd(url, payload)

    def get_authorization(self, auth_url):
        return self._cmd(auth_url, None)


def do(s443, *domains, accept_tos=False):
    # ensure args are valid
    if not accept_tos:
        raise AutocertError("CA's Terms of Service must be accepted")
    if not isinstance(s443, socket.socket):
        raise AutocertError('Socket s443 must be a socket')
#    if s443.getsockname()[1] != 443:
#        raise AutocertError('Socket s443 must be listening on port 443')

    client = ACMEClient(accept_tos=True)
    order = client.new_order(domains)
    print(order.headers['Location'])
    print(order.json())
    for auth_url in order.json()['authorizations']:
        authorization = client.get_authorization(auth_url)
        print(authorization)
        print(authorization.json())

        domain = authorization.json()['identifier']['value']
        print(domain)

        challenges = authorization.json()['challenges']
        challenge = [c for c in challenges if c['type'] == 'tls-alpn-01'][0]
        print(challenge)


if __name__ == '__main__':
    s80 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s80.bind(('0.0.0.0', 8080))
    s80.listen()

    # setup 80->443 redirect on s80
    srv = HTTPRedirectServer(s80)
    srv.start()

    s443 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s443.bind(('0.0.0.0', 8443))
    s443.listen()

    tls_s443 = do(s443, 'foobar.org', 'www.foobar.org', accept_tos=True)
