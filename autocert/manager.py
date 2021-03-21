from datetime import datetime, timedelta, timezone
import logging
import ssl
import time

from cryptography import x509

from autocert.errors import AutocertError

log = logging.getLogger(__name__)


class Manager:

    def __init__(self, private_key, context, cache, domains, client):
        self.private_key = private_key
        self.context = context
        self.cache = cache
        self.domains = domains
        self.client = client

        # setup primary domain and key / cert names
        self.primary_domain = domains[0]
        self.tls_pkey_name = self.primary_domain + '.pkey'
        self.tls_cert_name = self.primary_domain + '.cert'

        # setup key / cert file paths
        self.tls_pkey_path = self.cache.path(self.tls_pkey_name)
        self.tls_cert_path = self.cache.path(self.tls_cert_name)

        # flags to track when a TLS-ALPN-01 challenge is expected / in-progress
        self.expecting_challenge = False
        self.acme_tls_challenge = False

    def issue_and_renew_forever(self):
        log.info('starting issue/renew loop for domains: %s', self.domains)
        while True:
            # read cert from cache
            cert_pem = self.cache.read(self.tls_cert_name)

            # load as x509 and check TTL
            cert = x509.load_pem_x509_certificate(cert_pem)
            expiry = cert.not_valid_after
            expiry = expiry.replace(tzinfo=timezone.utc)

            # determine how many seconds remain until TTL is within 30 days
            remaining = expiry - datetime.now(timezone.utc) - timedelta(days=30)
            remaining = remaining.total_seconds()

            # sleep til the 30 day mark
            if remaining > 0:
                log.info('cert is still valid, sleeping for: %s', remaining)
                time.sleep(remaining)

            # time to issue / renew
            log.info('time is up, renewing cert for: %s', self.domains)
            self.issue_and_renew()

    def issue_and_renew(self):
        from pprint import pprint

        # TODO: check if order['status'] isn't pending for some reason
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
            acme_cert_name = domain + '.acme.cert'
            acme_cert_pem = self.private_key.generate_tls_alpn_01_cert(domain, keyauth)
            self.cache.write(acme_cert_name, acme_cert_pem)

            # get ready for challenge requests
            self.expecting_challenge = True

            # tell ACME server to verify our challenge
            challenge_url = challenge['url']
            self.client.verify_challenge(challenge_url)

            # poll til status isn't pending anymore
            # TODO: smarter backoff here
            auth = self.client.get_authorization(auth_url)
            while auth['status'] == 'pending':
                time.sleep(1)
                auth = self.client.get_authorization(auth_url)

            # challenge is over
            self.expecting_challenge = False

            pprint(auth)

            # at this point, we either failed or passed the challenge
            if auth['status'] != 'valid':
                raise AutocertError('failed to satisfy ACME challenge: {}'.format(auth))

        # generate CSR for new cert
        csr = self.private_key.generate_csr(self.domains)

        # finalize the order
        finalize_url = order['finalize']
        order = self.client.finalize_order(finalize_url, csr)
        pprint(order)

        # download the cert
        cert_url = order['certificate']
        cert_pem = self.client.download_certificate(cert_url)

        # replace certs in the cache
        self.cache.write(self.tls_cert_name, cert_pem)

        # update the managed SSLContext with the new cert chain
        self.context.load_cert_chain(self.tls_cert_path, self.tls_pkey_path)

    def msg_callback(self, conn, direction, version, content_type, msg_type, data):
        # early exit if not expecting a challenge
        if not self.expecting_challenge:
            return

        # else look for 'acme-tls/1' in the raw stream
        if direction == 'read' and b'acme-tls/1' in data:
            self.acme_tls_challenge = True
            log.info('!!! saw an acme-tls/1 request !!!')

    def sni_callback(self, sslsocket, sni_name, sslcontext):
        # early exit if not in a challenge
        if not self.acme_tls_challenge:
            return

        # ignore empty sni_name
        if sni_name is None:
            log.info('got an empty sni_name during a TLS-ALPN-01 challenge')
            return

        # make sure TLS-ALPN-01 challenge cert exists for this sni_name
        log.info('answering TLS-ALPN-01 challenge for: %s', sni_name)
        acme_cert_name = sni_name + '.acme.cert'
        if not self.cache.exists(acme_cert_name):
            log.info('missing TLS-ALPN-01 challenge cert: %s', acme_cert_name)
            return

        # create an ephemeral SSLContext for the challenge response
        ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        ctx.set_alpn_protocols(['acme-tls/1'])

        # HACK: fix deadlock until updates come through
        ctx._msg_callback = self.msg_callback

        # serve up the TLS-ALPN-01 challenge cert
        acme_cert_path = self.cache.path(acme_cert_name)
        ctx.load_cert_chain(acme_cert_path, self.tls_pkey_path)

        # update the socket with the new context
        sslsocket.context = ctx

        # reset acme_tls_challenge flag
        self.acme_tls_challenge = False
