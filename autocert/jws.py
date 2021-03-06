import json

from autocert.rfc4648 import base64url


class JWS(dict):

    def __init__(self, url, payload, nonce, jwk=None, kid=None):
        protected = self.encode_protected(url, nonce, jwk=jwk, kid=kid)
        payload = self.encode_payload(payload)
        jws = {
            'protected': protected,
            'payload': payload,
        }

        super().__init__(jws)

    def sign(self, private_key):
        protected = self['protected']
        payload = self['payload']

        signature = '{}.{}'.format(protected, payload)
        signature = signature.encode()
        signature = private_key.sign(signature)
        signature = base64url(signature)

        self['signature'] = signature
        return json.dumps(self, separators=(',', ':'))

    def encode_protected(self, url, nonce, jwk=None, kid=None):
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
        protected = base64url(protected)
        return protected

    def encode_payload(self, payload):
        if payload is None:
            return ''

        payload = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        payload = payload.encode()
        payload = base64url(payload)
        return payload 
