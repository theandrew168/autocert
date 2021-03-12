import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils

from autocert import utils


class JWS(dict):

    def __init__(self, url, payload, nonce, jwk=None, kid=None):
        if jwk is None and kid is None:
            raise ValueError('either "jwk" or "kid" must be specified')

        protected = self._encode_protected(url, nonce, jwk=jwk, kid=kid)
        payload = self._encode_payload(payload)
        jws = {
            'protected': protected,
            'payload': payload,
        }

        super().__init__(jws)

    def sign(self, private_key):
        self['signature'] = self._encode_signature(private_key)
        return json.dumps(self, separators=(',', ':'))

    def _encode_protected(self, url, nonce, jwk=None, kid=None):
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

    def _encode_payload(self, payload):
        if payload is None:
            return ''

        payload = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        payload = payload.encode()
        payload = utils.base64_rfc4648(payload)
        return payload 

    def _encode_signature(self, private_key):
        protected = self['protected']
        payload = self['payload']

        signature = '{}.{}'.format(protected, payload)
        signature = signature.encode()

        # https://community.letsencrypt.org/t/parse-error-reading-jws/137654/13
        signature = private_key.sign(
            signature,
            ec.ECDSA(hashes.SHA256()),
        )
        r, s = crypto_utils.decode_dss_signature(signature)
        r = utils.int_to_bytes(r)
        s = utils.int_to_bytes(s)
        signature = r + s

        signature = utils.base64_rfc4648(signature)
        return signature
