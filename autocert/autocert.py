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
