from datetime import datetime, timedelta, timezone
import hashlib
import logging
import os

import appdirs
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import requests

from autocert import crypto, utils
from autocert.cache import Cache
from autocert.jwk import JWK
from autocert.jws import JWS

#LETS_ENCRYPT_ACME_URL = 'https://acme-v02.api.letsencrypt.org/directory'
LETS_ENCRYPT_ACME_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'

log = logging.getLogger(__name__)


class ACMEClientError(Exception):
    pass


class ACMEClient:

    def __init__(self, cache, contact=None, accept_tos=False, directory_url=LETS_ENCRYPT_ACME_URL):
        if not accept_tos:
            raise ACMEClientError("CA's Terms of Service must be accepted")

        self.cache = cache
        self.contact = contact
        self.accept_tos = accept_tos
        self.directory_url = directory_url

        # grab current directory and initial nonce
        self.directory = requests.get(self.directory_url).json()
        self.nonce = requests.head(self.directory['newNonce']).headers['Replay-Nonce']

        # load existing ACME account or create a new one
        self._init_account()

    def create_order(self, domain):
        log.info('creating order for domain: %s', domain)
        url = self.directory['newOrder']
        payload = {
            'identifiers': [
                {'type': 'dns', 'value': domain},
            ],
        }
        resp = self._cmd(url, payload)
        return resp.json()

    def get_authorization(self, auth_url):
        log.info('getting authorization: %s', auth_url)
        resp = self._cmd(auth_url, None)
        return resp.json()

    def verify_challenge(self, challenge):
        log.info('verifying challenge: %s', challenge['url'])
        url = challenge['url']
        resp = self._cmd(url, {})
        return resp.json()

    def _init_account(self):
        # check if account (aka private key) already exists
        self.private_key = self._create_or_read_private_key('acme_account.pkey')

        # derive public key and json web key
        self.public_key = self.private_key.public_key()
        self.jwk = JWK.from_public_key(self.public_key)
        self.kid = None

        # create / read acme account
        acct = self._create_or_read_account()
        self.kid = acct.headers['Location']
        log.info('initialized account kid: %s', self.kid)

    def _create_or_read_private_key(self, name):
        if self.cache.exists(name):
            log.info('loading existing private key: %s', name)
            pem = self.cache.read(name)
            pkey = serialization.load_pem_private_key(pem, password=None)
            return pkey
        else:
            # generate a new pkey
            log.info('creating new private key: %s', name)
            pkey = ec.generate_private_key(ec.SECP256R1())
            pem = pkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self.cache.write(name, pem)
            return pkey

    def _create_or_read_account(self):
        url = self.directory['newAccount']
        payload = {
            'termsOfServiceAgreed': self.accept_tos,
        }

        # apply contact emails if present
        contact = self.contact
        if contact is not None:
            # if email is just a string, make it a single-element list
            if type(contact) == str:
                contact = [contact]

            log.info('attaching contact info to account: %s', contact)

            # add mailto prefix to each email if not already present
            emails = []
            for email in contact:
                if email.startswith('mailto:'):
                    emails.append(email)
                else:
                    emails.append('mailto:' + email)

            # add to payload
            payload['contact'] = emails

        return self._cmd(url, payload)

    def _cmd(self, url, payload):
        headers = {
            'Content-Type': 'application/jose+json',
        }
        jws = JWS(url, payload, self.nonce, jwk=self.jwk, kid=self.kid)
        jws = jws.sign(self.private_key)

        # post message to the ACME server
        resp = requests.post(url, headers=headers, data=jws)
        if resp.status_code not in [200, 201, 204]:
            # TODO: if bad nonce, get another and retry
            raise ACMEClientError('ACME error: {}'.format(resp.json()))

        # update nonce
        self.nonce = resp.headers['Replay-Nonce']

        return resp
