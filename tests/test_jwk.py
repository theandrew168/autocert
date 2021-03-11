from cryptography.hazmat.primitives.asymmetric import ec

from autocert import jwk


def test_public_key():
    pkey = ec.generate_private_key(curve=ec.SECP256R1())
    jwkey = jwk.from_public_key(pkey.public_key())
    assert jwkey['kty'] == 'EC'
    assert jwkey['crv'] == 'P-256'
    assert 'x' in jwkey
    assert 'y' in jwkey


def test_thumbprint():
    pkey = ec.generate_private_key(curve=ec.SECP256R1())
    jwkey = jwk.from_public_key(pkey.public_key())
    tp = jwk.thumbprint(jwkey)
    assert type(tp) == str
