from datetime import datetime, timedelta, timezone
import hashlib
import logging
import os

import appdirs
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import requests

from autocert import utils
from autocert.errors import AutocertError
from autocert.jwk import JWK
from autocert.jws import JWS

#LETS_ENCRYPT_ACME_URL = 'https://acme-v02.api.letsencrypt.org/directory'
LETS_ENCRYPT_ACME_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'

log = logging.getLogger(__name__)


class ACMEClient:

    def __init__(self, private_key, contact=None, accept_tos=False, directory_url=LETS_ENCRYPT_ACME_URL):
        if not accept_tos:
            raise AutocertError("CA's Terms of Service must be accepted")

        # initial ACME credentials
        self.private_key = private_key
        self.jwk = JWK(private_key.public_key)
        self.kid = None

        # other ACME details
        self.contact = contact
        self.accept_tos = accept_tos
        self.directory_url = directory_url

        # grab current directory and initial nonce
        self.directory = requests.get(self.directory_url).json()
        self.nonce = requests.head(self.directory['newNonce']).headers['Replay-Nonce']

        # load existing ACME account or create a new one
        acct = self._create_or_read_account()
        self.kid = acct.headers['Location']
        log.info('initialized account kid: %s', self.kid)

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

    def get_keyauth(self, token):
        thumbprint = self.jwk.thumbprint()
        keyauth = '{}.{}'.format(token, thumbprint)
        keyauth = keyauth.encode()
        return keyauth

    def finalize_order(self, finalize_url, csr):
        payload = {
            'csr': utils.base64_rfc4648(csr),
        }
        resp = self._cmd(finalize_url, payload)
        return resp.json()

    def download_certificate(self, cert_url):
        resp = self._cmd(cert_url, None)
        return resp.content

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
        resp = requests.post(url, headers=headers, data=jws)
        if resp.status_code not in [200, 201, 204]:
            # TODO: if bad nonce, get another and retry
            log.error('jws: %s', jws)
            log.error('url: %s', url)
            log.error('pay: %s', payload)
            log.error('nonce: %s', self.nonce)
            raise AutocertError('ACME error: {}'.format(resp.json()))

        # update nonce
        self.nonce = resp.headers['Replay-Nonce']

        return resp
