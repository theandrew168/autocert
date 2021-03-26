from autocert.acme import ACMEClient
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
