from datetime import datetime, timedelta, timezone
import hashlib
import logging
import pkgutil
import tempfile

import appdirs
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import requests

from autocert.jwk import JWK
from autocert.jws import JWS
from autocert.rfc4648 import base64url

LETS_ENCRYPT_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'
LETS_ENCRYPT_STAGING_DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
ACME_ERROR_BAD_NONCE = 'urn:ietf:params:acme:error:badNonce'
ACME_ERROR_MALFORMED = 'urn:ietf:params:acme:error:malformed'
ACME_ERROR_ORDER_NOT_READY = 'urn:ietf:params:acme:error:orderNotReady'


log = logging.getLogger(__name__)


class ACMEServerError(Exception):
    pass


class ACMEOrderNotReady(ACMEServerError):
    pass


class ACMEClient:

    def __init__(self, private_key, contact=None, accept_tos=False, directory_url=LETS_ENCRYPT_DIRECTORY_URL):
        # initial ACME credentials
        self.private_key = private_key
        self.jwk = JWK(private_key.public_key)
        self.kid = None

        # other ACME details
        if type(contact) == str:
            self.contact = [contact]
        else:
            self.contact = contact
        self.accept_tos = accept_tos
        self.directory_url = directory_url

        # use pebble's cert if directory_url contains localhost else use normal behavior
        self.verify_tls = True
        if 'localhost' in directory_url:
            pebble_cert = pkgutil.get_data(__package__, 'pebble.minica.pem')
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(pebble_cert)
                self.verify_tls = f.name

        # grab current directory and initial nonce
        self.directory = self._get_directory()
        self.nonce = self._get_nonce()

        # load existing ACME account or create a new one
        acct = self._create_or_read_account()
        self.kid = acct.headers['Location']
        log.info('initialized account kid: %s', self.kid)

    def get_keyauth(self, token):
        thumbprint = self.jwk.thumbprint()
        keyauth = '{}.{}'.format(token, thumbprint)
        keyauth = keyauth.encode()
        return keyauth

    def create_order(self, domains):
        log.info('creating order for domains: %s', domains)
        url = self.directory['newOrder']
        payload = {
            'identifiers': [
                {'type': 'dns', 'value': domain} for domain in domains
            ],
        }
        resp = self._cmd(url, payload)
        return resp.json()

    def get_authorization(self, auth_url):
        log.info('getting authorization: %s', auth_url)
        resp = self._cmd(auth_url, None)
        return resp.json()

    def verify_challenge(self, challenge_url):
        log.info('verifying challenge: %s', challenge_url)
        resp = self._cmd(challenge_url, {})
        return resp.json()

    def finalize_order(self, finalize_url, csr):
        payload = {
            'csr': base64url(csr),
        }
        resp = self._cmd(finalize_url, payload)
        return resp.json()

    def download_certificate(self, cert_url):
        resp = self._cmd(cert_url, None)
        return resp.content

    def _get_directory(self):
        directory = requests.get(self.directory_url, verify=self.verify_tls)
        directory = directory.json()
        return directory

    def _get_nonce(self):
        nonce = requests.head(self.directory['newNonce'], verify=self.verify_tls)
        nonce = nonce.headers['Replay-Nonce']
        return nonce

    def _create_or_read_account(self):
        url = self.directory['newAccount']
        payload = {
            'termsOfServiceAgreed': self.accept_tos,
        }

        # apply contact emails if present
        contact = self.contact
        if contact is not None:
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
        resp = requests.post(url, headers=headers, data=jws, verify=self.verify_tls)
        if resp.status_code not in [200, 201, 204]:
            resp = resp.json()

            # if bad / malformed nonce, get another and retry
            if resp['type'] in [ACME_ERROR_BAD_NONCE, ACME_ERROR_MALFORMED]:
                self.nonce = self._get_nonce()
                return self._cmd(url, payload)

            if resp['type'] == ACME_ERROR_ORDER_NOT_READY:
                raise ACMEOrderNotReady()

            raise ACMEServerError(resp)

        # update nonce
        self.nonce = resp.headers['Replay-Nonce']

        return resp
