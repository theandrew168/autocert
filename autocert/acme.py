from datetime import datetime, timedelta, timezone
import hashlib
import os

import appdirs
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid
import requests

from autocert import utils
from autocert.jwk import JWK
from autocert.jws import JWS

#LETS_ENCRYPT_ACME_URL = 'https://acme-v02.api.letsencrypt.org/directory'
LETS_ENCRYPT_ACME_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'

# OID for the ACME extension for the TLS-ALPN challenge.
# https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-05#section-5.1
ID_PE_ACME_IDENTIFIER = x509.ObjectIdentifier('1.3.6.1.5.5.7.1.31')


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
        self._init_account()

    def get_domain_key(self, domain):
        key_path = os.path.join(self.cache_dir, domain + '.key')
        return self._create_or_read_key(key_path)

    def get_domain_cert(self, domain):
        cert_path = os.path.join(self.cache_dir, domain + '.cert')

    def create_order(self, domains):
        url = self.directory['newOrder']
        payload = {
            'identifiers': [{'type': 'dns', 'value': domain} for domain in domains],
        }
        resp = self._cmd(url, payload)
        return resp.json()

    def get_authorization(self, auth_url):
        resp = self._cmd(auth_url, None)
        return resp.json()

    def verify_challenge(self, challenge):
        url = challenge['url']
        resp = self._cmd(url, {})
        return resp.json()

    def _create_or_read_key(self, path):
        if os.path.exists(path):
            # load pkey from cache
            with open(path, 'rb') as f:
                pem = f.read()
            return serialization.load_pem_private_key(pem, password=None)
        else:
            # generate a new pkey
            pkey = ec.generate_private_key(ec.SECP256R1())
            pem = pkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            # save pkey to cache
            with open(path, 'wb') as f:
                f.write(pem)
            return pkey

    def _init_account(self):
        # check if account (aka private key) already exists
        acct_path = os.path.join(self.cache_dir, 'acme_account')
        self.private_key = self._create_or_read_key(acct_path)

        # derive public key and json web key
        self.public_key = self.private_key.public_key()
        self.jwk = JWK.from_public_key(self.public_key)
        self.kid = None

        # create / read acme account
        acct = self._create_or_read_account()
        self.kid = acct.headers['Location']

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


def generate_tls_alpn_01_key_cert(challenge, domain, jwk):
    # create the keyauth value
    token = challenge['token']
    thumbprint = jwk.thumbprint()
    keyauth = '{}.{}'.format(token, thumbprint)
    keyauth = keyauth.encode()

    # create the ACME identifier
    acme_identifier = hashlib.sha256(keyauth).digest()
    acme_identifier = utils.bytes_to_der(acme_identifier)

    # generate a private key for this cert
    private_key = ec.generate_private_key(curve=ec.SECP256R1())
    public_key = private_key.public_key()

    # convert private key to PEM
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # https://cryptography.io/en/latest/x509/reference.html#x-509-certificate-builder
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, 'ACME Challenge'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, 'ACME Challenge'),
    ]))
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(7, 0, 0))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(domain),
        ]),
        critical=True,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            oid.ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=True,
    )
    builder = builder.add_extension(
        # https://github.com/pyca/cryptography/issues/2747
        x509.UnrecognizedExtension(ID_PE_ACME_IDENTIFIER, acme_identifier),
        critical=True,
    )
    builder = builder.public_key(public_key)

    # sign the cert and convert to PEM
    cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return key_pem, cert_pem
