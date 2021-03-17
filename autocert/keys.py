from datetime import datetime, timedelta, timezone
import hashlib
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from autocert import utils

# OID for the ACME extension for the TLS-ALPN challenge.
# https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-05#section-5.1
ID_PE_ACME_IDENTIFIER = x509.ObjectIdentifier('1.3.6.1.5.5.7.1.31')

log = logging.getLogger(__name__)


class PrivateKey:

    def __init__(self, pem=None):
        if pem is not None:
            self.key = serialization.load_pem_private_key(pem, password=None)
            self.pem = pem
        else:
            self.key = ec.generate_private_key(curve=ec.SECP256R1())
            self.pem = self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

        self.public_key = PublicKey(self.key.public_key())

    def sign(self, data):
        # https://community.letsencrypt.org/t/parse-error-reading-jws/137654/13
        signature = self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = crypto_utils.decode_dss_signature(signature)
        r = utils.int_to_bytes(r)
        s = utils.int_to_bytes(s)
        signature = r + s
        return signature

    def generate_csr(self, domains):
        # https://cryptography.io/en/latest/x509/reference.html#x-509-csr-certificate-signing-request-builder-object
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
        ]))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(domain) for domain in domains]
            ),
            critical=True,
        )

        # sign the cert and convert to DER
        csr = builder.sign(private_key=self.key, algorithm=hashes.SHA256())
        csr = csr.public_bytes(serialization.Encoding.DER)
        return csr

    def generate_self_signed_cert(self, domains, ttl=timedelta(days=30)):
        # https://cryptography.io/en/latest/x509/reference.html#x-509-certificate-builder
        builder = x509.CertificateBuilder()
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
        ]))
        builder = builder.not_valid_before(datetime.now(timezone.utc))
        builder = builder.not_valid_after(datetime.now(timezone.utc) + ttl)
        builder = builder.public_key(self.key.public_key())
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(domain) for domain in domains]
            ),
            critical=True
        )

        # sign the cert and convert to PEM
        cert = builder.sign(private_key=self.key, algorithm=hashes.SHA256())
        cert = cert.public_bytes(serialization.Encoding.PEM)
        return cert

    def generate_tls_alpn_01_cert(self, domain, keyauth, ttl=timedelta(days=30)):
        # create the ACME identifier
        acme_identifier = hashlib.sha256(keyauth).digest()
        acme_identifier = utils.bytes_to_der(acme_identifier)

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
        builder = builder.not_valid_after(datetime.now(timezone.utc) + ttl)
        builder = builder.public_key(self.key.public_key())
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

        # sign the cert and convert to PEM
        cert = builder.sign(private_key=self.key, algorithm=hashes.SHA256())
        cert = cert.public_bytes(serialization.Encoding.PEM)
        return cert


class PublicKey:
    NIST_CURVE_NAMES = {
        'secp192r1': 'P-192',
        'secp224r1': 'P-224',
        'secp256r1': 'P-256',
        'secp384r1': 'P-384',
        'secp521r1': 'P-521',
    }

    def __init__(self, key):
        self.key = key
        self.pem = self.key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def curve(self):
        curve = self.key.curve.name
        curve = self.NIST_CURVE_NAMES[curve]
        return curve

    @property
    def x(self):
        x = self.key.public_numbers().x
        x = utils.int_to_bytes(x)
        return x

    @property
    def y(self):
        y = self.key.public_numbers().y
        y = utils.int_to_bytes(y)
        return y
