import base64


# https://tools.ietf.org/html/rfc4648#section-5
def base64url(b):
    return base64.urlsafe_b64encode(b).decode().replace('=', '')
