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
]

client = acme.ACMEClient(accept_tos=True)

order = client.create_order(domains)
pprint(order)

auth = client.get_authorization(order)
pprint(auth)

k, c = challenge.generate_tls_alpn_01_cert(auth, client.jwk)
print(k)
print(c)
