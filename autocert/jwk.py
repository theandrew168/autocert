import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ec

from autocert import utils

NIST_CURVE_NAMES = {
    'secp192r1': 'P-192',
    'secp224r1': 'P-224',
    'secp256r1': 'P-256',
    'secp384r1': 'P-384',
    'secp521r1': 'P-521',
}


def from_public_key(public_key):
    if public_key.curve.name not in NIST_CURVE_NAMES:
        raise ValueError('unsupported curve: {}'.format(public_key.curve.name))

    crv = NIST_CURVE_NAMES[public_key.curve.name]
    x = utils.int_to_bytes(public_key.public_numbers().x)
    y = utils.int_to_bytes(public_key.public_numbers().y)

    jwk = {
        'kty': 'EC',
        'crv': crv,
        'x': utils.base64_rfc4648(x),
        'y': utils.base64_rfc4648(y),
    }
    return jwk


def thumbprint(jwk):
    jwk = json.dumps(jwk, separators=(',', ':'), sort_keys=True)
    jwk = jwk.encode()
    sha256_hash = hashlib.sha256(jwk).digest()
    return utils.base64_rfc4648(sha256_hash)
