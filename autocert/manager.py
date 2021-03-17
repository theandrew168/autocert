from datetime import datetime, timedelta, timezone
import logging
import time

from cryptography import x509

log = logging.getLogger(__name__)


class Manager:

    def __init__(self, private_key, cache, domains, client):
        self.private_key = private_key
        self.cache = cache
        self.domains = domains
        self.client = client

        # setup primary domain and key / cert names
        self.primary_domain = domains[0]
        self.tls_pkey_name = self.primary_domain + '.pkey'
        self.tls_cert_name = self.primary_domain + '.cert'
        self.tls_cert_acme_name = self.primary_domain + '.cert.acme'

        # setup key / cert file paths
        self.tls_pkey_path = self.cache.path(self.tls_pkey_name)
        self.tls_cert_path = self.cache.path(self.tls_cert_name)
        self.tls_cert_acme_path = self.cache.path(self.tls_cert_acme_name)

        # flags to track when a TLS-ALPN-01 challenge is expected / in-progress
        self.expecting_challenge = False
        self.acme_tls_challenge = False

    def issue_and_renew_forever(self):
        log.info('starting issue/renew loop for domains: %s', self.domains)
        while True:
            # load cert from cache
            cert_pem = self.cache.read(self.tls_cert_name)

            # import and check TTL
            cert = x509.load_pem_x509_certificate(cert_pem)
            expiry = cert.not_valid_after
            expiry = expiry.replace(tzinfo=timezone.utc)

            # determine how many seconds remain until TTL is within 30 days
            remaining = expiry - datetime.now(timezone.utc) - timedelta(days=30)
            remaining = remaining.total_seconds()

            # sleep til the 30 day mark
            if remaining > 0:
                log.info('certs are still valid, sleeping for: %s', remaining)
                time.sleep(remaining.total_seconds())

            # time to issue / renew
            log.info('time is up, renewing certs for: %s', self.domains)
            self.issue_and_renew()

    def issue_and_renew(self):
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
        # early exit if not in a challenge
        if not self.acme_tls_challenge:
            sslcontext.load_cert_chain(self.tls_cert_path, self.tls_pkey_path)
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

        # serve up the TLS-ALPN-01 challenge cert
        acme_cert_path = self.cache.path(acme_cert_name)
        sslcontext.load_cert_chain(acme_cert_path, self.tls_pkey_path)

        # reset acme_tls_challenge flag
        self.acme_tls_challenge = False

    def msg_callback(self, conn, direction, version, content_type, msg_type, data):
        # early exit if not expecting a challenge
        if not self.expecting_challenge:
            return

        # else look for 'acme-tls/1' in the raw stream
        if direction == 'read' and b'acme-tls/1' in data:
            self.acme_tls_challenge = True
            log.info('!!! saw an acme-tls/1 request !!!')
