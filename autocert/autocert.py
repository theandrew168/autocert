from datetime import datetime, timedelta, timezone
import os
import socket
import ssl
import tempfile
import threading
import time

import appdirs
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import oid

from autocert import acme
from autocert.cache import Cache


class ACMEInterceptor:

    def __init__(self, cache, domains, client):
        self.cache = cache
        self.domains = domains
        self.client = client

    # Fluent Python: Chapter 21 - Class Metaprogramming
    def make_sslsocket_class(self):
        def do_handshake(self):
            super().do_handshake()
            alpn_protocol = self.selected_alpn_protocol()
            print('handshake:', alpn_protocol)

            # swap to ACME challenge chain if requested
            if alpn_protocol == 'acme-tls/1':
                key_path = self.cache.path(self.domain + '.key')
                cert_path = self.cache.path(self.domain + '.cert.acme')
                self.context.load_cert_chain(cert_path, key_path)

        def set_domain(self, domain):
            self.domain = domain

        cls_attrs = {
            'interceptor': self,
            'do_handshake': do_handshake,
            'set_domain': set_domain,
            'domain': None,
        }

        return type('ACMEInterceptorSocket', ssl.SSLSocket.__mro__, cls_attrs)

    def sni_callback(self, acmesocket, sni_name, sslcontext):
        print('got request for: {}'.format(sni_name))

        # nothing to do for empty sni_name
        if sni_name is None:
            print('got an unknown sni_name, bailing out')
            return

        key_name = sni_name + '.key'
        cert_name = sni_name + '.cert'
        if not self.cache.exists(key_name) or not self.cache.exists(cert_name):
            print('got an unknown sni_name, bailing out')
            return

        key_path = self.cache.path(key_name)
        cert_path = self.cache.path(cert_name)

        # load regular chain for sni_name and set socket domain
        sslcontext.load_cert_chain(cert_path, key_path)
        acmesocket.set_domain(sni_name)


def do(s443, *domains, contact=None, accept_tos=False):
    # ensure args are valid
    if not accept_tos:
        raise AutocertError("CA's Terms of Service must be accepted")
    if not isinstance(s443, socket.socket):
        raise AutocertError('Socket s443 must be a socket')
#    if s443.getsockname()[1] != 443:
#        raise AutocertError('Socket s443 must be listening on port 443')

    # use a platform-friendly directory for caching keys / certs
    cache_dir = appdirs.user_cache_dir('python-autocert', 'python-autocert')

    # client writes to the cache and interceptor reads from it
    cache = Cache(cache_dir)
    client = acme.ACMEClient(cache, contact=contact, accept_tos=accept_tos)
    interceptor = ACMEInterceptor(cache, domains, client)

    # create self-signed certs for each domain if none exist
    for domain in domains:
        print('checking key / cert for:', domain)
        key_name = domain + '.key'
        cert_name = domain + '.cert'
        if cache.exists(key_name) and cache.exists(cert_name):
            continue

        # generate a private key for this cert
        key = ec.generate_private_key(curve=ec.SECP256R1())

        # convert private key to PEM
        key_pem = key.private_bytes(
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
        builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(90, 0, 0))
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
            ]),
            critical=True,
        )
        builder = builder.public_key(key.public_key())

        # sign the cert and convert to PEM
        cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        cache.write(key_name, key_pem)
        cache.write(cert_name, cert_pem)

    # create ssl context w/ modern cipher and ability to accept acme-tls/1
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.set_ciphers('ECDHE+AESGCM')
    ctx.set_alpn_protocols(['acme-tls/1', 'h2', 'spdy/2', 'http/1.1'])
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    # hook interceptor into the context
    ctx.sslsocket_class = interceptor.make_sslsocket_class()
    ctx.sni_callback = interceptor.sni_callback

    # wrap and return the TLS-enabled socket
    s443_tls = ctx.wrap_socket(s443, server_side=True)
    return s443_tls




#    from pprint import pprint
#
#    order = client.create_order(domains)
#    pprint(order)
#
#    auth_urls = order['authorizations']
#    for auth_url in auth_urls:
#        auth = client.get_authorization(auth_url)
#        pprint(auth)
#
#        # pull out the domain and TLS-ALPN-01 challenge
#        domain = auth['identifier']['value']
#        challenge = [c for c in auth['challenges'] if c['type'] == 'tls-alpn-01'][0]
#
#
#        ctx.sslsocket_class = make_acme_intercept_socket(client)
#        ctx.set_ciphers('ECDHE+AESGCM')
#        ctx.set_alpn_protocols(['acme-tls/1'])
#        ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
#        ctx.sni_callback = load_cert
#        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
#
#        # start the SSL server
#        s443_tls = ctx.wrap_socket(s443, server_side=True)
#        def accept_loop():
#            print('started sock_tls accept loop')
#            while True:
#                try:
#                    conn, addr = s443_tls.accept()
#                    #conn_tls = ctx.wrap_socket(conn, server_side=True)
#                    print('***********************')
#                    print('got conn from: {}'.format(addr))
#                    print('***********************')
#                    conn.recv(1)
#                    conn.close()
#                except Exception as e:
#                    print(e)
#
#        t = threading.Thread(target=accept_loop, daemon=True)
#        t.start()
#
#        # tell ACME server to check
#        client.verify_challenge(challenge)
#
#        # wait til not pending
#        while auth['status'] == 'pending':
#            time.sleep(5)
#            auth = client.get_authorization(auth_url)
#            pprint(auth)
#
#        # TODO: create CSR
#        # TODO: finalize order
#        # TODO: update context with valid chain
#        # TODO: schedule renew
#
#        # return the SSL-wrapped socket
#        return s443_tls
