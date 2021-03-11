from pprint import pprint
import socket
import threading
import time

from autocert import acme, challenge, wsgi
from cryptography.hazmat.primitives.asymmetric import ec
import waitress

s80 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s80.bind(('0.0.0.0', 8080))
s80.listen()

t = threading.Thread(
    target=waitress.serve,
    args=(wsgi.redirect_app,),
    kwargs={'sockets': [s80]},
    daemon=True,
)
t.start()

domains = [
    'example.org',
    'www.example.org',
]

client = acme.ACMEClient(accept_tos=True)

order = client.create_order(domains)
pprint(order)

auths = client.get_authorizations(order)
for auth in auths:
    pprint(auth)
    # pull out the domain and TLS-ALPN-01 challenge
    domain = auth['identifier']['value']
    chal_tls_alpn_01 = [c for c in auth['challenges'] if c['type'] == 'tls-alpn-01'][0]

    key, cert = challenge.generate_tls_alpn_01_key_cert(chal_tls_alpn_01, domain, client.jwk)
    print(key)
    print(cert)

    # TODO: start the SSL server
    # TODO: tell ACME server to check
    # TODO: wait til not pending
