"""
https://tools.ietf.org/html/rfc8555

https://github.com/golang/crypto/tree/master/acme/autocert
https://github.com/farrepa/django-autocert/tree/develop/autocert

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

LETS_ENCRYPT_ACME_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'


class AutocertError(Exception):
    pass


def do(s80, s443, *domains, accept_tos=False):
    if not accept_tos:
        raise AutocertError('Terms of Service not accepted')

    cache_dir = appdirs.user_cache_dir('python-autocert', 'python-autocert')
    print(cache_dir)

    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)


if __name__ == '__main__':
    do(80, 443, 'foobar.org', 'www.foobar.org', accept_tos=True)
