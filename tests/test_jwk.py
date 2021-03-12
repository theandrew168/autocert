from cryptography.hazmat.primitives.asymmetric import ec

from autocert.jwk import JWK


def test_public_key():
    pkey = ec.generate_private_key(curve=ec.SECP256R1())
    jwk = JWK.from_public_key(pkey.public_key())
    assert jwk['kty'] == 'EC'
    assert jwk['crv'] == 'P-256'
    assert 'x' in jwk
    assert 'y' in jwk


def test_thumbprint():
    pkey = ec.generate_private_key(curve=ec.SECP256R1())
    jwk = JWK.from_public_key(pkey.public_key())
    thumb = jwk.thumbprint()
    assert type(thumb) == str
