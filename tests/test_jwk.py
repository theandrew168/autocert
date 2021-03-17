from cryptography.hazmat.primitives.asymmetric import ec

from autocert.jwk import JWK
from autocert.keys import PrivateKey


def test_public_key():
    pkey = PrivateKey()
    jwk = JWK.from_public_key(pkey.public_key)
    assert jwk['kty'] == 'EC'
    assert jwk['crv'] == 'P-256'
    assert 'x' in jwk
    assert 'y' in jwk


def test_thumbprint():
    pkey = PrivateKey()
    jwk = JWK.from_public_key(pkey.public_key)
    thumb = jwk.thumbprint()
    assert type(thumb) == str
