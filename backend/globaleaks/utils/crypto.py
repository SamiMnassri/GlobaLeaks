import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography import x509

import datetime

from six import binary_type, text_type

class AsyncCryptographyContext(object):
    '''Provides cryptographic services based on x509 certificates'''

    def __init__(self):
        self.certificate = None
        self.private_key = None

        self.certificate_pem = None
        self.private_key_pem = None

    def _serialize_private_key(self, passphrase):
        self.private_key_pem = text_type(self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(binary_type(passphrase, 'utf-8'))
        ), 'ascii')

    def _private_key_required(self):
        if self.private_key is None:
            raise ValueError("Operation only available with private key")

    def generate_private_key(self, passphrase):
        '''Generates a private key and initialize the CryptographyContext'''
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._serialize_private_key(passphrase)

    def encrypt_data(self, data):
        '''Encrypts data
        
        Data is encrypted in Base64-ed output
        '''
        ciphertext = self.certificate.public_key().encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(ciphertext).decode()

    def decrypt_data(self, data):
        '''Decrypts data'''

        ciphertext = base64.b64decode(data)
        cleartext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return cleartext

    @classmethod
    def load_full_keyset(cls, private_key_pem, certificate_pem, passphrase):
        '''Loads the full keyset, and decrypts the private key in memory'''
        context = cls()
        context.certificate_pem = certificate_pem
        context.private_key_pem = private_key_pem

        context.private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=passphrase,
            backend=default_backend()
        )

        context.certificate = x509.load_pem_x509_certificate(
            certification_pem,
            default_backend()
        )

    def change_private_key_password(self, new_passphrase):
        '''Changes the passphrase on the private key. The result can be read from private_key_pem
        or from return value'''
        self._private_key_required()
        self._serialize_private_key(new_passphrase)
        return self.private_key_pem

    def generate_self_signed_certificate(self, common_name):
        '''Generates a self-signed certificate'''
        self._private_key_required()

        # This isn't really "right", but when it gets right down to it, for x509 certificates, the only thing
        # that actually matters is the CN. For S/MIME certificates, cn == email address, web addresses for HTTP,
        # and MAGIC for x.501 (yes, I've actually seen these in the wild). However, if we're manually checking
        # certificates like we're doing as of writing in GL, we can pretty much set CN to anything.
        #
        # For our purposes, we'll set the CN to the username of the user, or string of the receipt_hash if a
        # whistleblower so we can identify them from the PEM certificate alone. We *might* want to encode
        # tenant id here somewhere.

         # Self-signed certs use the same issuer/subject
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)
        ])

        self.certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # FIXME: determine SANE length
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).sign(self.private_key, hashes.SHA256(), default_backend())

        self.certificate_pem = text_type(
            self.certificate.public_bytes(serialization.Encoding.PEM), 'ascii'
        )