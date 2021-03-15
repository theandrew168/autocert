from datetime import datetime, timedelta, timezone
import hashlib
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from autocert import utils
from autocert.cache import Cache

# OID for the ACME extension for the TLS-ALPN challenge.
# https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-05#section-5.1
ID_PE_ACME_IDENTIFIER = x509.ObjectIdentifier('1.3.6.1.5.5.7.1.31')

log = logging.getLogger(__name__)


def generate_self_signed_chain(domain):
    # generate a private key for this cert
    pkey = ec.generate_private_key(curve=ec.SECP256R1())
    pkey_pem = pkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # https://cryptography.io/en/latest/x509/reference.html#x-509-certificate-builder
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ]))
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc))
    builder = builder.public_key(pkey.public_key())

    # sign the cert and convert to PEM
    cert = builder.sign(private_key=pkey, algorithm=hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return pkey_pem, cert_pem


def generate_tls_alpn_01_chain(domain, keyauth):
    # create the ACME identifier
    acme_identifier = hashlib.sha256(keyauth).digest()
    acme_identifier = utils.bytes_to_der(acme_identifier)

    # generate a private key for this cert
    pkey = ec.generate_private_key(ec.SECP256R1())
    pkey_pem = pkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # https://cryptography.io/en/latest/x509/reference.html#x-509-certificate-builder
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'ACME Challenge'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'ACME Challenge'),
    ]))
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=7))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(domain),
        ]),
        critical=True,
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=True,
    )
    builder = builder.add_extension(
        # https://github.com/pyca/cryptography/issues/2747
        x509.UnrecognizedExtension(ID_PE_ACME_IDENTIFIER, acme_identifier),
        critical=True,
    )
    builder = builder.public_key(pkey.public_key())

    # sign the cert and convert to PEM
    cert = builder.sign(private_key=pkey, algorithm=hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    return pkey_pem, cert_pem
