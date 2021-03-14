from datetime import datetime, timedelta, timezone
import logging
import socket
import ssl
import threading
import time

import appdirs
from cryptography import x509

from autocert import acme, crypto
from autocert.cache import Cache

log = logging.getLogger(__name__)


class ACMEInterceptor:

    def __init__(self, cache, domains, client):
        self.cache = cache
        self.domains = domains
        self.client = client
        self.expecting_challenge = False
        self.acme_tls_challenge = False

    def schedule_renewals(self):
        for domain in self.domains:
            thread = threading.Thread(
                target=self.renewal_loop,
                args=(domain,),
                daemon=True
            )
            thread.start()

    def renewal_loop(self, domain):
        # check cert for domain
        # if not exists
        #     gen pkey
        #     do an ACME flow (order, challenge, finalize, CSR, cert)
        #     update cert
        # else if lifetime < 30 days:
        #     do an ACME flow (order, challenge, finalize, CSR, cert)
        #     update cert
        # 
        # sleep timer till 30 days before expire
        log.info('started renewal loop for: %s', domain)

        pkey_name = domain + '.pkey'
        cert_name = domain + '.cert'
        pkey_path = self.cache.path(pkey_name)
        cert_path = self.cache.path(cert_name)

        # create an expired self-signed chain
        if not self.cache.exists(pkey_name) or not self.cache.exists(cert_name):
            log.info('generating self-signed cert for: %s', domain)
            pkey_pem, cert_pem = crypto.generate_self_signed_chain(domain)

            log.info('adding self-signed chain to cache: %s', domain)
            self.cache.write(pkey_name, pkey_pem)
            self.cache.write(cert_name, cert_pem)

        while True:
            pkey_pem = self.cache.read(pkey_name)
            cert_pem = self.cache.read(cert_name)

            # load cert and check remaining validity
            cert = x509.load_pem_x509_certificate(cert_pem)
            expires = cert.not_valid_after
            expires = expires.replace(tzinfo=timezone.utc)

            # check how many seconds remain until the 30 day point
            remaining = expires - datetime.now(timezone.utc) - timedelta(days=30)
            remaining = remaining.total_seconds()

            # sleep til the 30 day mark
            if remaining > 0:
                log.info('cert still valid, sleeping for: %s', remaining)
                time.sleep(remaining.total_seconds())

            # time to renew
            log.info('time is up, renewing cert for: %s', domain)
            self.do_renewal(domain)

    def do_renewal(self, domain):
        log.info('renewing cert for: %s', domain)
        from pprint import pprint
        order = self.client.create_order(domain)
        pprint(order)
        auth_urls = order['authorizations']
        for auth_url in auth_urls:
            auth = self.client.get_authorization(auth_url)
            pprint(auth)

            # pull out the domain and TLS-ALPN-01 challenge
            domain = auth['identifier']['value']
            challenge = [c for c in auth['challenges'] if c['type'] == 'tls-alpn-01'][0]

            # TODO: HACKY: create the keyauth value
            token = challenge['token']
            thumbprint = self.client.jwk.thumbprint()
            keyauth = '{}.{}'.format(token, thumbprint)
            keyauth = keyauth.encode()

            # generate the TLS-ALPN-01 challenge chain
            pkey_name = domain + '.pkey.acme'
            cert_name = domain + '.cert.acme'
            pkey_pem, cert_pem = crypto.generate_tls_alpn_01_chain(domain, keyauth)
            self.cache.write(pkey_name, pkey_pem)
            self.cache.write(cert_name, cert_pem)

            # get ready for challenge requests
            self.expecting_challenge = True

            # tell LE to check
            self.client.verify_challenge(challenge)

            # poll til status isn't pending anymore
            auth = self.client.get_authorization(auth_url)
            while auth['status'] == 'pending':
                time.sleep(1)
                auth = self.client.get_authorization(auth_url)

            pprint(auth)

    def sni_callback(self, sslsocket, sni_name, sslcontext):
        log.info('got SNI request for: %s', sni_name)

        # nothing to do for empty sni_name
        if sni_name is None:
            log.info('empty sni_name')
            return

        pkey_name = sni_name + '.pkey'
        cert_name = sni_name + '.cert'
        pkey_path = self.cache.path(pkey_name)
        cert_path = self.cache.path(cert_name)

        # check if pkey / cert exists for SNI name
        if not self.cache.exists(pkey_name) or not self.cache.exists(cert_name):
            log.info('invalid sni_name or chain doesnt exist yet: %s', sni_name)
            return

        # else, load up a different chain
        log.info('loading pkey: %s', pkey_path)
        log.info('loading cert: %s', cert_path)
        sslcontext.load_cert_chain(cert_path, pkey_path)

        # reset acme_tls_challenge flag
        self.acme_tls_challenge = False

    def msg_callback(self, conn, direction, version, content_type, msg_type, data):
        if direction == 'read' and b'acme-tls/1' in data:
            self.acme_tls_challenge = True
            log.info('acme-tls/1 request from: %s', conn.raddr)
            log.info('content-type: %s', content_type)


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

    # client writes to the cache and interceptor reads from it
    cache = Cache(cache_dir)
    client = acme.ACMEClient(cache, contact=contact, accept_tos=accept_tos)
    interceptor = ACMEInterceptor(cache, domains, client)

    # generate default self-signed cert
    default_pkey_name = 'default.pkey'
    default_cert_name = 'default.cert'
    if not cache.exists(default_pkey_name) or not cache.exists(default_cert_name):
        log.info('generating default chain')
        pkey_pem, cert_pem = crypto.generate_self_signed_chain('default')

        log.info('adding default chain to cache')
        cache.write(default_pkey_name, pkey_pem)
        cache.write(default_cert_name, cert_pem)

    pkey_path = cache.path(default_pkey_name)
    cert_path = cache.path(default_cert_name)

    # create ssl context w/ modern cipher and ability to accept acme-tls/1
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.set_ciphers('ECDHE+AESGCM')
    ctx.set_alpn_protocols(['acme-tls/1', 'http/1.1'])
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    ctx.load_cert_chain(cert_path, pkey_path)

    # hook interceptor into the context
    ctx.sni_callback = interceptor.sni_callback
    ctx._msg_callback = interceptor.msg_callback

    # schedule cert renewals
    interceptor.schedule_renewals()

    # wrap and return the TLS-enabled socket
    sock_tls = ctx.wrap_socket(sock, server_side=True)
    return sock_tls
