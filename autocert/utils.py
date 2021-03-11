import base64


def base64_rfc4648(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace('=', '')


def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')


def bytes_to_der(b):
    if len(b) >= 128:
        raise ValueError('bytes_to_der only works for small bytes (< 128)')

    octet_string = 0x04
    header = [octet_string, len(b)]
    return bytes(header) + b
