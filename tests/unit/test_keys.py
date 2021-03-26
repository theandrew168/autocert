from cryptography import x509
from cryptography.x509 import oid
import pytest

from autocert.keys import ID_PE_ACME_IDENTIFIER
from autocert.keys import bytes_to_der, int_to_bytes, keyauth_to_acme_identifier
from autocert.keys import PrivateKey, PublicKey


@pytest.mark.parametrize(
    'i,      b', [
    (0,      '00'),
    (1,      '01'),
    (255,    'ff'),
    (256,    '0100'),
    (65534,  'fffe'),
    (65535,  'ffff'),
    (0xfffe, 'fffe'),
    (0xffff, 'ffff'),
])
def test_int_to_bytes(i, b):
    assert int_to_bytes(i).hex() == b


def test_bytes_to_der():
    b = b'\xff\xff\xff\xff\xff'
    d = bytes_to_der(b)
    assert d == b'\x04\x05\xff\xff\xff\xff\xff'


def test_bytes_to_der_too_large():
    b = b'\xff' * 128
    with pytest.raises(ValueError):
        d = bytes_to_der(b)


def test_private_key():
    pkey = PrivateKey()
    assert type(pkey.pem) == bytes


def test_private_key_from_pem():
    pem = PrivateKey().pem
    pkey = PrivateKey(pem)
    assert type(pkey.pem) == bytes


def test_private_key_sign():
    pkey = PrivateKey()
    data = b'oh wow some data'
    sig = pkey.sign(data)
    assert type(sig) == bytes


def test_private_key_generate_csr():
    domains = ['example.org', 'www.example.org']

    pkey = PrivateKey()
    csr = pkey.generate_csr(domains)
    assert type(csr) == bytes

    csr = x509.load_der_x509_csr(csr)
    subject = csr.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)[0]
    assert subject.value == domains[0]

    ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    sans = ext.get_values_for_type(x509.DNSName)
    assert sans == domains


def test_private_key_generate_self_signed_cert():
    domains = ['example.org', 'www.example.org']

    pkey = PrivateKey()
    cert = pkey.generate_self_signed_cert(domains)
    assert type(cert) == bytes

    cert = x509.load_pem_x509_certificate(cert)
    subject = cert.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)[0]
    assert subject.value == domains[0]
    issuer = cert.issuer.get_attributes_for_oid(oid.NameOID.COMMON_NAME)[0]
    assert issuer.value == domains[0]

    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    sans = ext.get_values_for_type(x509.DNSName)
    assert sans == domains


def test_private_key_generate_tls_alpn_01_cert():
    domain = 'example.org'
    keyauth = b'foobarkeyauth'
    acme_identifier = keyauth_to_acme_identifier(keyauth)

    pkey = PrivateKey()
    cert = pkey.generate_tls_alpn_01_cert(domain, keyauth)
    assert type(cert) == bytes

    cert = x509.load_pem_x509_certificate(cert)
    subject = cert.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)[0]
    assert subject.value == domain
    issuer = cert.issuer.get_attributes_for_oid(oid.NameOID.COMMON_NAME)[0]
    assert issuer.value == domain

    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    sans = ext.get_values_for_type(x509.DNSName)
    assert sans[0] == domain

    ext = cert.extensions.get_extension_for_oid(ID_PE_ACME_IDENTIFIER).value
    assert ext.value == acme_identifier


def test_public_key():
    pkey = PrivateKey()
    pubkey = pkey.public_key
    assert pubkey.curve in PublicKey.NIST_CURVE_NAMES.values()
    assert type(pubkey.x) == bytes
    assert type(pubkey.y) == bytes
