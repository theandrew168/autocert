import os

import appdirs
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import requests

from autocert import jwk, jws


#LETS_ENCRYPT_ACME_URL = 'https://acme-v02.api.letsencrypt.org/directory'
LETS_ENCRYPT_ACME_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'


class ACMEClientError(Exception):
    pass


class ACMEClient:

    def __init__(self, accept_tos=False, directory_url=LETS_ENCRYPT_ACME_URL):
        if not accept_tos:
            raise ACMEClientError("CA's Terms of Service must be accepted")

        self.accept_tos = accept_tos
        self.directory_url = directory_url

        # grab current directory and initial nonce
        self.directory = requests.get(self.directory_url).json()
        self.nonce = requests.head(self.directory['newNonce']).headers['Replay-Nonce']

        # ensure autocert cache dir exists
        self.cache_dir = appdirs.user_cache_dir('python-autocert', 'python-autocert')
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

        # load existing ACME account or create a new one
        self.init_account()

    def init_account(self):
        # check if account (aka private key) already exists
        acct_path = os.path.join(self.cache_dir, 'acme_account')
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

        # derive public key and json web key
        self.public_key = self.private_key.public_key()
        self.jwk = jwk.from_public_key(self.public_key)
        self.kid = None

        # create / read acme account
        acct = self._create_or_read_account()
        self.kid = acct.headers['Location']

    def create_order(self, domains):
        url = self.directory['newOrder']
        payload = {
            'identifiers': [{'type': 'dns', 'value': domain} for domain in domains],
        }
        resp = self._cmd(url, payload)
        return resp.json()

    def get_authorizations(self, order):
        urls = order['authorizations']
        for url in urls:
            resp = self._cmd(url, None)
            yield resp.json()

    def _create_or_read_account(self):
        url = self.directory['newAccount']
        payload = {
            'termsOfServiceAgreed': self.accept_tos,
        }
        return self._cmd(url, payload)

    def _cmd(self, url, payload):
        headers = {
            'Content-Type': 'application/jose+json',
        }
        data = jws.encode(url, payload, self.nonce, self.private_key, jwk=self.jwk, kid=self.kid)

        # post message to the ACME server
        resp = requests.post(url, headers=headers, data=data)
        if resp.status_code not in [200, 201, 204]:
            # TODO: if bad nonce, get another and retry
            raise ACMEClientError('ACME error: {}'.format(resp.json()))

        # update nonce
        self.nonce = resp.headers['Replay-Nonce']

        return resp
