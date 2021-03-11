import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils

from autocert import utils


def encode(url, payload, nonce, private_key, jwk=None, kid=None):
    if jwk is None and kid is None:
        raise ValueError('either "jwk" or "kid" must be specified')

    protected = encode_protected(url, nonce, jwk=jwk, kid=kid)
    payload = encode_payload(payload)
    signature = encode_signature(protected, payload, private_key)

    jws = {
        'protected': protected,
        'payload': payload,
        'signature': signature,
    }
    jws = json.dumps(jws, separators=(',', ':'))
    return jws


def encode_protected(url, nonce, jwk=None, kid=None):
    if jwk is None and kid is None:
        raise ValueError('either "jwk" or "kid" must be specified')

    protected = {
        'alg': 'ES256',
        'nonce': nonce,
        'url': url,
    }
    # use kid if present else default to jwk
    if kid is not None:
        protected['kid'] = kid
    else:
        protected['jwk'] = jwk

    protected = json.dumps(protected, separators=(',', ':'), sort_keys=True)
    protected = protected.encode()
    protected = utils.base64_rfc4648(protected)
    return protected


def encode_payload(payload):
    if payload is None:
        return ''

    payload = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    payload = payload.encode()
    payload = utils.base64_rfc4648(payload)
    return payload 


def encode_signature(protected, payload, private_key):
    signature = '{}.{}'.format(protected, payload)
    signature = signature.encode()
    signature = sign(signature, private_key)
    signature = utils.base64_rfc4648(signature)
    return signature


def sign(signature, private_key):
    # https://community.letsencrypt.org/t/parse-error-reading-jws/137654/13
    signature = private_key.sign(
        signature,
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = crypto_utils.decode_dss_signature(signature)
    r = utils.int_to_bytes(r)
    s = utils.int_to_bytes(s)
    return r + s
