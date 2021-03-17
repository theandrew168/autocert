import hashlib
import json

from autocert import utils


class JWK(dict):

    @classmethod
    def from_public_key(cls, public_key):
        jwk = {
            'kty': 'EC',
            'crv': public_key.curve,
            'x': utils.base64_rfc4648(public_key.x),
            'y': utils.base64_rfc4648(public_key.y),
        }
        return cls(jwk)

    def thumbprint(self):
        thumbprint = json.dumps(self, separators=(',', ':'), sort_keys=True)
        thumbprint = thumbprint.encode()
        thumbprint = hashlib.sha256(thumbprint).digest()
        thumbprint = utils.base64_rfc4648(thumbprint)
        return thumbprint
