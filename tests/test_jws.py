from cryptography.hazmat.primitives.asymmetric import ec

from autocert import jwk, jws


def test_encode_jwk():
    pkey = ec.generate_private_key(curve=ec.SECP256R1())
    jwkey = jwk.from_public_key(pkey.public_key())

    url = 'http://example.org'
    payload = {
        'answer': 42,
        'cat': 'dog',
    }
    nonce = 'abc123nonce'
    sig = jws.encode(url, payload, nonce, pkey, jwk=jwkey)
    assert 'protected' in sig
    assert 'payload' in sig
    assert 'signature' in sig


def test_encode_kid():
    pkey = ec.generate_private_key(curve=ec.SECP256R1())
    kid = 'http://example.org/myaccount'

    url = 'http://example.org'
    payload = {
        'answer': 42,
        'cat': 'dog',
    }
    nonce = 'abc123nonce'
    sig = jws.encode(url, payload, nonce, pkey, kid=kid)
    assert 'protected' in sig
    assert 'payload' in sig
    assert 'signature' in sig


def test_encode_empty_payload():
    pkey = ec.generate_private_key(curve=ec.SECP256R1())
    jwkey = jwk.from_public_key(pkey.public_key())

    url = 'http://example.org'
    payload = None
    nonce = 'abc123nonce'
    sig = jws.encode(url, payload, nonce, pkey, jwk=jwkey)
    assert 'protected' in sig
    assert 'payload' in sig
    assert 'signature' in sig
