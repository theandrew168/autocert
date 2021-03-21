from datetime import datetime, timedelta, timezone
import logging
import socket
import ssl
import threading

import appdirs

from autocert.acme import ACMEClient
from autocert.cache import Cache
from autocert.errors import AutocertError
from autocert.keys import PrivateKey
from autocert.manager import Manager

log = logging.getLogger(__name__)


def manage(sock, *domains, contact=None, accept_tos=False):
    # ensure args are valid
    if not accept_tos:
        raise AutocertError("CA's Terms of Service must be accepted")
    if not isinstance(sock, socket.socket):
        raise AutocertError('Socket sock must be a socket')

    # if contact email is just a string, make it a single-element list
    if type(contact) == str:
        contact = [contact]

    # use a platform-friendly directory for caching keys / certs
    cache_dir = appdirs.user_cache_dir('python-autocert', 'python-autocert')
    log.info('using cache dir: %s', cache_dir)
    cache = Cache(cache_dir)

    # ensure account pkey exists
    account_pkey_name = 'account_acme.pkey'
    if cache.exists(account_pkey_name):
        log.info('loading existing account key: %s', account_pkey_name)
        account_pkey_pem = cache.read(account_pkey_name)
        account_pkey = PrivateKey(account_pkey_pem)
    else:
        log.info('generating new account key: %s', account_pkey_name)
        account_pkey = PrivateKey()
        account_pkey_pem = account_pkey.pem
        cache.write(account_pkey_name, account_pkey_pem)

    # first domain in the list will be the subject (all domains will be SANs)
    primary_domain = domains[0]
    tls_pkey_name = primary_domain + '.pkey'
    tls_cert_name = primary_domain + '.cert'

    # read or create TLS pkey
    tls_pkey = None
    if cache.exists(tls_pkey_name):
        tls_pkey_pem = cache.read(tls_pkey_name)
        tls_pkey = PrivateKey(tls_pkey_pem)
    else:
        tls_pkey = PrivateKey()
        tls_pkey_pem = tls_pkey.pem
        cache.write(tls_pkey_name, tls_pkey_pem)

    # ensure TLS cert exists (defaults to a self-signed cert)
    if not cache.exists(tls_cert_name):
        tls_cert_pem = tls_pkey.generate_self_signed_cert(domains)
        cache.write(tls_cert_name, tls_cert_pem)

    # create ssl context w/ modern ciphers/options
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)

    # SSLContext.load_cert_chain wants real files :(
    tls_pkey_path = cache.path(tls_pkey_name)
    tls_cert_path = cache.path(tls_cert_name)
    ctx.load_cert_chain(tls_cert_path, tls_pkey_path)

    # init ACME client and cert manager
    client = ACMEClient(account_pkey, contact=contact, accept_tos=accept_tos)
    manager = Manager(tls_pkey, ctx, cache, domains, client)

    # hook manager into the context
    ctx._msg_callback = manager.msg_callback
    ctx.sni_callback = manager.sni_callback

    # kick off cert issuance and renewal loop in a background thread
    thread = threading.Thread(
        target=manager.issue_and_renew_forever,
        daemon=True,
    )
    thread.start()

    # wrap and return the TLS-enabled socket
    sock_tls = ctx.wrap_socket(sock, server_side=True)
    return sock_tls
