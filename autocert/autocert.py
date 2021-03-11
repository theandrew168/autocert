import base64
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import socket
import ssl
from threading import Thread

import appdirs
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509 import oid
import requests


class ACMEClient:

    def do_tls_alpn_01_challenge(self, domain, challenge):
        print(domain)

        token = challenge['token']
        keyauth = '.'.join([token, self.thumbprint])

        shasum = hashlib.sha256(keyauth.encode()).digest()
        value = bytes_to_der(shasum)

        # https://cryptography.io/en/latest/x509/reference.html#x-509-certificate-builder
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(oid.NameOID.COMMON_NAME, domain),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(oid.NameOID.COMMON_NAME, domain),
        ]))
        builder = builder.not_valid_before(datetime.now(timezone.utc))
        builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(7, 0, 0))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(self.public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            # digital_signature and key_encipherment
            x509.KeyUsage(True, False, True, False, False, False, False, False, False),
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
            x509.UnrecognizedExtension(ID_PE_ACME_IDENTIFIER, value),
            critical=True,
        )
        cert = builder.sign(private_key=self.private_key, algorithm=hashes.SHA256())
        cert = cert.public_bytes(serialization.Encoding.PEM).decode()

        # create an SSLContext and add our cert
        ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        ctx.set_ciphers('ECDHE+AESGCM')
        ctx.set_alpn_protocols(['acme-tls/1'])
        ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        ctx.load_verify_locations(cadata=cert)
        print(ctx.cert_store_stats())


def do(s443, *domains, accept_tos=False):
    # ensure args are valid
    if not accept_tos:
        raise AutocertError("CA's Terms of Service must be accepted")
    if not isinstance(s443, socket.socket):
        raise AutocertError('Socket s443 must be a socket')
#    if s443.getsockname()[1] != 443:
#        raise AutocertError('Socket s443 must be listening on port 443')

    client = ACMEClient(accept_tos=True)
    order = client.new_order(domains)
    print(order.headers['Location'])
    print(order.json())
    for auth_url in order.json()['authorizations']:
        authorization = client.get_authorization(auth_url)
        domain = authorization.json()['identifier']['value']

        challenges = authorization.json()['challenges']
        challenge = [c for c in challenges if c['type'] == 'tls-alpn-01'][0]

        client.do_tls_alpn_01_challenge(domain, challenge)
