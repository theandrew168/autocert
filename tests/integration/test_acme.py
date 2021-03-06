import pytest

from autocert.acme import ACMEClient
from autocert.acme import ACMEOrderNotReady, ACME_ERROR_ORDER_NOT_READY
from autocert.keys import PrivateKey

PEBBLE_DIRECTORY_URL = 'https://localhost:14000/dir'


def test_init():
    pkey = PrivateKey()
    client = ACMEClient(pkey, accept_tos=True, directory_url=PEBBLE_DIRECTORY_URL)
    assert type(client.directory) == dict
    assert 'newAccount' in client.directory
    assert 'newOrder' in client.directory

    assert client.nonce is not None
    assert client.jwk is not None
    assert client.kid is not None


def test_init_single_contact():
    contact = 'foo@example.org'

    pkey = PrivateKey()
    client = ACMEClient(pkey, contact=contact, accept_tos=True, directory_url=PEBBLE_DIRECTORY_URL)
    assert client.contact == [contact]


def test_init_multiple_contact():
    contact = ['foo@example.org', 'bar@example.org']

    pkey = PrivateKey()
    client = ACMEClient(pkey, contact=contact, accept_tos=True, directory_url=PEBBLE_DIRECTORY_URL)
    assert client.contact == contact


def test_get_keyauth():
    pkey = PrivateKey()
    client = ACMEClient(pkey, accept_tos=True, directory_url=PEBBLE_DIRECTORY_URL)

    token = 'foobar_nice_token'
    keyauth = client.get_keyauth(token)
    assert type(keyauth) == bytes
    assert b'.' in keyauth


def test_create_order():
    domains = ['example.org', 'www.example.org']

    pkey = PrivateKey()
    client = ACMEClient(pkey, accept_tos=True, directory_url=PEBBLE_DIRECTORY_URL)

    order = client.create_order(domains)
    assert order['status'] == 'pending'
    assert len(order['identifiers']) == len(domains)
    assert len(order['authorizations']) == len(domains)


def test_get_authorization():
    domains = ['example.org', 'www.example.org']

    pkey = PrivateKey()
    client = ACMEClient(pkey, accept_tos=True, directory_url=PEBBLE_DIRECTORY_URL)

    order = client.create_order(domains)
    for auth_url in order['authorizations']:
        auth = client.get_authorization(auth_url)
        assert auth['status'] == 'pending'
        types = [challenge['type'] for challenge in auth['challenges']]
        assert 'tls-alpn-01' in types


def test_verify_challenge():
    domains = ['example.org', 'www.example.org']

    pkey = PrivateKey()
    client = ACMEClient(pkey, accept_tos=True, directory_url=PEBBLE_DIRECTORY_URL)

    order = client.create_order(domains)
    for auth_url in order['authorizations']:
        auth = client.get_authorization(auth_url)
        assert auth['status'] == 'pending'
        challenge = [challenge for challenge in auth['challenges']
                     if challenge['type'] == 'tls-alpn-01'][0]
        challenge_url = challenge['url']
        challenge = client.verify_challenge(challenge_url)
        assert challenge['status'] == 'pending'


def test_finalize_order():
    domains = ['example.org', 'www.example.org']

    pkey = PrivateKey()
    client = ACMEClient(pkey, accept_tos=True, directory_url=PEBBLE_DIRECTORY_URL)
    order = client.create_order(domains)

    finalize_url = order['finalize']
    csr = pkey.generate_csr(domains)

    with pytest.raises(ACMEOrderNotReady):
        order = client.finalize_order(finalize_url, csr)
