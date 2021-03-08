"""
https://tools.ietf.org/html/rfc8555
https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md

https://github.com/golang/crypto/tree/master/acme/autocert
https://github.com/farrepa/django-autocert/tree/develop/autocert
https://github.com/diafygi/acme-tiny

https://docs.python.org/3/library/socket.html
https://docs.python.org/3/library/ssl.html


The game plan:
--------------

cache dir exists (appdirs)?
if exists:
    import
    check renew now
    schedule renew
else:
    obtain
    schedule renew

kick off renew thread (renew at 30 day mark +/- 30 mins jitter)
keep track of the SSLContext used to create the SSLSocket
when new cert is acquired:
    update the cache (appdirs)
    call context.load_cert_chain()

new clients from accept() should now get the new stuff
old ones will still have the "old" cert but that's fine (still valid)
"""
import os
import socket
import ssl

import appdirs
import requests

#LETS_ENCRYPT_ACME_URL = 'https://acme-v02.api.letsencrypt.org/directory'
LETS_ENCRYPT_ACME_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'


class AutocertError(Exception):
    pass


def do(s80, s443, *domains, accept_tos=False):
    # ensure args are valid
    if not accept_tos:
        raise AutocertError("CA's Terms of Service must be accepted")
    if not isinstance(s80, socket.socket):
        raise AutocertError('Socket s80 must be a socket')
    if not isinstance(s443, socket.socket):
        raise AutocertError('Socket s443 must be a socket')
#    if s80.getsockname()[1] != 80:
#        raise AutocertError('Socket s80 must be listening on port 80')
#    if s443.getsockname()[1] != 443:
#        raise AutocertError('Socket s443 must be listening on port 443')

    # ensure TLS cert cache dir exists
    cache_dir = appdirs.user_cache_dir('python-autocert', 'python-autocert')
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)

    d = requests.get(LETS_ENCRYPT_ACME_URL)
    print(d.json())


if __name__ == '__main__':
    s80 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s80.bind(('0.0.0.0', 8080))
    s80.listen()

    s443 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s443.bind(('0.0.0.0', 8443))
    s443.listen()

    do(s80, s443, 'foobar.org', 'www.foobar.org', accept_tos=True)
