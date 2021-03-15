from datetime import datetime, timedelta, timezone
import logging
import socket
import ssl
import threading
import time

import appdirs
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from autocert import acme, certs
from autocert.cache import Cache

log = logging.getLogger(__name__)


class ACMEInterceptorError(Exception):
    pass


class ACMEInterceptor:

    def __init__(self, cache, domains, client):
        self.cache = cache
        self.domains = domains
        self.client = client

        # flags to track when a TLS-ALPN-01 challenge is expected / in-progress
        self.expecting_challenge = False
        self.acme_tls_challenge = False

        # create a self-signed cert for each domain (will get replaced)
        for domain in self.domains:
            self._init_cert(domain)

    def issue_and_renew_forever(self):
        log.info('starting issue/renew loop for domains: %s', self.domains)
        while True:
            earliest_expiry = min(self._check_expiry(d) for d in self.domains)

            # determine how many seconds remain until TTL is within 30 days
            remaining = earliest_expiry - datetime.now(timezone.utc) - timedelta(days=30)
            remaining = remaining.total_seconds()

            # sleep til the 30 day mark
            if remaining > 0:
                log.info('certs are still valid, sleeping for: %s', remaining)
                time.sleep(remaining.total_seconds())

            # time to renew
            log.info('time is up, renewing certs for: %s', self.domains)
            self._do_renewal()

    def _init_cert(self, domain):
        pkey_name = domain + '.pkey'
        cert_name = domain + '.cert'

        # create an expired self-signed chain
        if not self.cache.exists(pkey_name) or not self.cache.exists(cert_name):
            log.info('generating initial self-signed cert for: %s', domain)
            pkey_pem, cert_pem = certs.generate_self_signed_chain(domain)
            self.cache.write(pkey_name, pkey_pem)
            self.cache.write(cert_name, cert_pem)
        else:
            log.info('cert already exists for: %s', domain)

    def _check_expiry(self, domain):
        # load cert from cache
        cert_name = domain + '.cert'
        cert_pem = self.cache.read(cert_name)

        # import and check TTL
        cert = x509.load_pem_x509_certificate(cert_pem)
        expires = cert.not_valid_after
        expires = expires.replace(tzinfo=timezone.utc)
        return expires

    def _do_renewal(self):
        from pprint import pprint
        log.info('renewing certs for: %s', self.domains)

        order = self.client.create_order(self.domains)
        pprint(order)
        auth_urls = order['authorizations']
        for auth_url in auth_urls:
            auth = self.client.get_authorization(auth_url)
            pprint(auth)

            # pull out the domain and TLS-ALPN-01 challenge
            domain = auth['identifier']['value']
            challenge = [c for c in auth['challenges'] if c['type'] == 'tls-alpn-01'][0]

            # determine the keyauth value
            token = challenge['token']
            keyauth = self.client.get_keyauth(token)

            # generate the TLS-ALPN-01 challenge chain
            pkey_name = domain + '.pkey.acme'
            cert_name = domain + '.cert.acme'
            pkey_pem, cert_pem = certs.generate_tls_alpn_01_chain(domain, keyauth)
            self.cache.write(pkey_name, pkey_pem)
            self.cache.write(cert_name, cert_pem)

            # get ready for challenge requests
            self.expecting_challenge = True

            # tell ACME server to verify our challenge
            self.client.verify_challenge(challenge)

            # poll til status isn't pending anymore
            auth = self.client.get_authorization(auth_url)
            while auth['status'] == 'pending':
                time.sleep(1)
                auth = self.client.get_authorization(auth_url)

            # challenge is over
            self.expecting_challenge = False

            pprint(auth)

            # at this point, we either failed or passed the challenge
            if auth['status'] != 'valid':
                raise ACMEInterceptorError('failed to satisfy ACME challenge: {}'.format(auth))

        print('TODO: generate CSRs')
        print('TODO: finalize the order')
        print('TODO: download the certs')
        print('TODO: replace certs in the cache')
        time.sleep(10)
        return

    def sni_callback(self, sslsocket, sni_name, sslcontext):
        log.info('got SNI request for: %s', sni_name)

        # nothing to do for empty sni_name
        if sni_name is None:
            log.info('empty sni_name')
            return

        # determine which chain to serve up
        pkey_name = sni_name + '.pkey'
        cert_name = sni_name + '.cert'
        if self.acme_tls_challenge:
            pkey_name += '.acme'
            cert_name += '.acme'

        pkey_path = self.cache.path(pkey_name)
        cert_path = self.cache.path(cert_name)

        # check if pkey / cert exists for SNI name
        if not self.cache.exists(pkey_name) or not self.cache.exists(cert_name):
            log.info('invalid sni_name or chain doesnt exist yet: %s', sni_name)
            return

        # TODO: optimize this to avoid a load_cert_chain on every request
        # else, load up a different chain
        log.info('loading pkey: %s', pkey_path)
        log.info('loading cert: %s', cert_path)
        sslcontext.load_cert_chain(cert_path, pkey_path)

        # reset acme_tls_challenge flag
        self.acme_tls_challenge = False

    def msg_callback(self, conn, direction, version, content_type, msg_type, data):
        # early exit if not expecting a challenge
        if not self.expecting_challenge:
            return

        # else look for 'acme-tls/1' in the raw stream
        if direction == 'read' and b'acme-tls/1' in data:
            self.acme_tls_challenge = True
            log.info('saw an acme-tls/1 request')


def do(sock, *domains, contact=None, accept_tos=False):
    # ensure args are valid
    if not accept_tos:
        raise AutocertError("CA's Terms of Service must be accepted")
    if not isinstance(sock, socket.socket):
        raise AutocertError('Socket sock must be a socket')
#    if sock.getsockname()[1] != 443:
#        raise AutocertError('Socket sock must be listening on port 443')

    # use a platform-friendly directory for caching keys / certs
    cache_dir = appdirs.user_cache_dir('python-autocert', 'python-autocert')
    cache = Cache(cache_dir)

    # load account pkey if it exists otherwise create one
    account_pkey_name = 'account_acme.pkey'
    account_pkey = create_or_read_private_key(cache, account_pkey_name)

    # init ACME client and challenge interceptor
    client = acme.ACMEClient(account_pkey, contact=contact, accept_tos=accept_tos)
    interceptor = ACMEInterceptor(cache, domains, client)

    # generate default self-signed cert
    default_pkey_name = 'default.pkey'
    default_cert_name = 'default.cert'
    default_pkey_path = cache.path(default_pkey_name)
    default_cert_path = cache.path(default_cert_name)
    if not cache.exists(default_pkey_name) or not cache.exists(default_cert_name):
        log.info('generating default chain')
        pkey_pem, cert_pem = certs.generate_self_signed_chain('default')

        log.info('adding default chain to cache')
        cache.write(default_pkey_name, pkey_pem)
        cache.write(default_cert_name, cert_pem)

    # create ssl context w/ default chain and ability to accept acme-tls/1
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.set_ciphers('ECDHE+AESGCM')
    ctx.set_alpn_protocols(['acme-tls/1', 'http/1.1'])
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    ctx.load_cert_chain(default_cert_path, default_pkey_path)

    # hook interceptor into the context
    ctx.sni_callback = interceptor.sni_callback
    ctx._msg_callback = interceptor.msg_callback

    # kick off cert issuance and renewal loop in a background thread
    thread = threading.Thread(
        target=interceptor.issue_and_renew_forever,
        daemon=True,
    )
    thread.start()

    # wrap and return the TLS-enabled socket
    sock_tls = ctx.wrap_socket(sock, server_side=True)
    return sock_tls


def create_or_read_private_key(cache, name):
    if cache.exists(name):
        log.info('loading existing private key: %s', name)
        pem = cache.read(name)
        pkey = serialization.load_pem_private_key(pem, password=None)
        return pkey
    else:
        log.info('generating new private key: %s', name)
        pkey = ec.generate_private_key(ec.SECP256R1())
        pem = pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cache.write(name, pem)
        return pkey
