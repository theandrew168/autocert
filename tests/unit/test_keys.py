from autocert.keys import PrivateKey, PublicKey


def test_private_key():
    pkey = PrivateKey()
    assert type(pkey.pem) == bytes


def test_private_key_from_pem():
    pem = PrivateKey().pem
    pkey = PrivateKey(pem)
    assert type(pkey.pem) == bytes


def test_public_key():
    pkey = PrivateKey()
    pubkey = pkey.public_key
    assert pubkey.curve in PublicKey.NIST_CURVE_NAMES.values()
    assert type(pubkey.x) == bytes
    assert type(pubkey.y) == bytes
