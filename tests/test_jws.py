from autocert.jwk import JWK
from autocert.jws import JWS
from autocert.keys import PrivateKey


def test_sign_with_jwk():
    pkey = PrivateKey()
    jwk = JWK.from_public_key(pkey.public_key)

    url = 'http://example.org'
    payload = {
        'answer': 42,
        'cat': 'dog',
    }
    nonce = 'abc123nonce'
    jws = JWS(url, payload, nonce, jwk=jwk)
    jws = jws.sign(pkey)

    assert type(jws) == str
    assert 'protected' in jws
    assert 'payload' in jws
    assert 'signature' in jws


def test_sign_with_kid():
    pkey = PrivateKey()
    kid = 'http://example.org/myaccount'

    url = 'http://example.org'
    payload = {
        'answer': 42,
        'cat': 'dog',
    }
    nonce = 'abc123nonce'
    jws = JWS(url, payload, nonce, kid=kid)
    jws = jws.sign(pkey)

    assert type(jws) == str
    assert 'protected' in jws
    assert 'payload' in jws
    assert 'signature' in jws


def test_sign_with_empty_payload():
    pkey = PrivateKey()
    jwk = JWK.from_public_key(pkey.public_key)

    url = 'http://example.org'
    payload = None
    nonce = 'abc123nonce'
    jws = JWS(url, payload, nonce, jwk=jwk)
    jws = jws.sign(pkey)

    assert type(jws) == str
    assert 'protected' in jws
    assert 'payload' in jws
    assert 'signature' in jws
