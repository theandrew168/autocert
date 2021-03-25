from autocert.rfc4648 import base64url


def test_base64url():
    data = b'oh wow some data'
    encoded = base64url(data)
    assert type(encoded) == str
    assert '=' not in encoded
