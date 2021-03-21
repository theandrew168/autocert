import hashlib
import json

from autocert.rfc4648 import base64url


class JWK(dict):

    def __init__(self, public_key):
        jwk = {
            'kty': 'EC',
            'crv': public_key.curve,
            'x': base64url(public_key.x),
            'y': base64url(public_key.y),
        }
        super().__init__(jwk)

    def thumbprint(self):
        thumbprint = json.dumps(self, separators=(',', ':'), sort_keys=True)
        thumbprint = thumbprint.encode()
        thumbprint = hashlib.sha256(thumbprint).digest()
        thumbprint = base64url(thumbprint)
        return thumbprint
