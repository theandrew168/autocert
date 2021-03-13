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
        print('started renewal loop for:', domain)
        # TODO: check cert for domain
        # TODO: if not exists
        # TODO:     gen pkey
        # TODO:     do an ACME flow (order, challenge, finalize, CSR, cert)
        # TODO:     update cert
        # TODO: else if lifetime < 30 days:
        # TODO:     do an ACME flow (order, challenge, finalize, CSR, cert)
        # TODO:     update cert
        # TODO:
        # TODO: sleep timer till 30 days before expire

    def sni_callback(self, sslsocket, sni_name, sslcontext):
        print('got request for: {}'.format(sni_name))

        # nothing to do for empty sni_name
        if sni_name is None:
            print('empty sni_name')
            return

        key_name = sni_name + '.key'
        cert_name = sni_name + '.cert'

        if not self.cache.exists(key_name) or not self.cache.exists(cert_name):
            print('invalid sni_name or chain doesnt exist yet:', sni_name)
            return

        # else, load up a different chain
        key_path = self.cache.path(key_name)
        cert_path = self.cache.path(cert_name)

        # load regular chain for sni_name and set socket domain
        print('loading key', key_path)
        print('loading cert', cert_path)
        sslcontext.load_cert_chain(cert_path, key_path)

        # reset acme_tls_challenge flag
        self.acme_tls_challenge = False

    def msg_callback(self, conn, direction, version, content_type, msg_type, data):
        if direction == 'read' and b'acme-tls/1' in data:
            self.acme_tls_challenge = True
            print('acme-tls/1 request from:', conn.raddr)
            print('content-type:', content_type)


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
    default_key_name = 'default.key'
    default_cert_name = 'default.cert'
    if not cache.exists(default_key_name) or not cache.exists(default_cert_name):
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
            x509.NameAttribute(oid.NameOID.COMMON_NAME, 'default'),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(oid.NameOID.COMMON_NAME, 'default'),
        ]))
        builder = builder.not_valid_before(datetime.now(timezone.utc))
        builder = builder.not_valid_after(datetime.now(timezone.utc))
        builder = builder.public_key(key.public_key())

        # sign the cert and convert to PEM
        cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        cache.write(default_key_name, key_pem)
        cache.write(default_cert_name, cert_pem)

    # create ssl context w/ modern cipher and ability to accept acme-tls/1
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.set_ciphers('ECDHE+AESGCM')
    ctx.set_alpn_protocols(['acme-tls/1', 'http/1.1'])
    ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    ctx.load_cert_chain(cache.path(default_cert_name), cache.path(default_key_name))

    # hook interceptor into the context
    ctx.sni_callback = interceptor.sni_callback
    ctx._msg_callback = interceptor.msg_callback

    # schedule cert renewals
    interceptor.schedule_renewals()

    # wrap and return the TLS-enabled socket
    sock_tls = ctx.wrap_socket(sock, server_side=True)
    return sock_tls




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
#        sock_tls = ctx.wrap_socket(sock, server_side=True)
#        def accept_loop():
#            print('started sock_tls accept loop')
#            while True:
#                try:
#                    conn, addr = sock_tls.accept()
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
#        return sock_tls
