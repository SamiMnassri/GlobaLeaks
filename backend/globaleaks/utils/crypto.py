import base64

import codecs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

import datetime

from six import binary_type, text_type
import json
import os

import scrypt

class AsymmetricalCryptographyContext(object):
    '''Provides cryptographic services based on x509 certificates'''

    def __init__(self):
        self.certificate = None
        self.private_key = None

        self.certificate_pem = None
        self.private_key_pem = None

    def _serialize_private_key(self, passphrase):
        # If passphrase is none, we're not encrypted
        if not isinstance(passphrase, binary_type):
            passphrase = passphrase.encode('ascii')

        self.private_key_pem = text_type(self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(binary_type(passphrase))
        ), 'ascii')

    def _private_key_required(self):
        if self.private_key is None:
            raise ValueError("Operation only available with private key")

    @staticmethod
    def derive_scrypted_passphrase(base_pw, salt):
        '''Derieves a passphrase based off 15 rounds of scrypt. The result hex encoded '''

        # This was incredibly annoying to get a consistent result from Py2/Py
        hash_str = scrypt.hash(base_pw, salt, N=1<<15)

        return text_type(codecs.encode(hash_str, 'hex'), 'ascii')

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
        context._load_public_key(certificate_pem)

        context.private_key_pem = private_key_pem

        if isinstance(passphrase, text_type):
            passphrase = passphrase.encode('ascii')

        context.private_key = serialization.load_pem_private_key(
            binary_type(private_key_pem, 'ascii'),
            password=passphrase,
            backend=default_backend()
        )
        return context

    @classmethod
    def load_public_key(cls, certificate_pem):
        context = cls()
        context._load_public_key(certificate_pem)
        return context

    def _load_public_key(self, certificate_pem):
        self.certificate_pem = certificate_pem
        self.certificate = x509.load_pem_x509_certificate(
            binary_type(certificate_pem, 'ascii'),
            default_backend()
        )

    def change_private_key_password(self, new_passphrase):
        '''Changes the passphrase on the private key. The result can be read from private_key_pem
        or from return value'''
        self._private_key_required()
        self._serialize_private_key(new_passphrase)
        return self.private_key_pem

    def get_decrypted_private_key(self):
        '''Returns the decrypted private key'''

        return text_type(self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ), 'ascii')

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
        if not isinstance(common_name, text_type):
            common_name = common_name.decode('ascii')

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

class SymmetricalCryptographyContext(object):
    '''Implements symmetrical cryptography and provides databasable (that's a word)
    blobs that we can load to and from the database in Base64 form
    
    Currently only supports AESGCM environment.

    self.key is in ASCII form ready for loading/unloading
    '''

    def __init__(self):
        self.key = None

    def _need_key(self):
        if self.key is None:
            raise ValueError("Need private key")

    @classmethod
    def load_key(cls, key):
        context = cls()
        context.key = key
        return context

    def generate_key(self):
        self.key = base64.b64encode(
            AESGCM.generate_key(bit_length=256)
        ).decode()

    def encrypt_data(self, data):
        '''Encrypts a bytes-like object , and returns it in base64 encoded form'''

        self._need_key()
        # So AES-GCM is an interesting beast. We need two bits of data, a private key, and
        # an initialize vector (this is different from say ChaCha20). To make this API
        # algo generic, we'll encode the data in base64 form, then return a json structure
        # that contains some basic information, and the initialization vector
        #
        # The IV *must* be different from encrypted blob to encrypted blob so we'll generate
        # it here, and not expose it publicly in our API

        initialization_vector = os.urandom(12)

        aes_obj = AESGCM(base64.b64decode(self.key))
        encrypted_data = aes_obj.encrypt(initialization_vector, data, None)

        return json.dumps({
            'algorithm': 'AESGCM256',
            'initialization_vector': base64.b64encode(initialization_vector).decode(),
            'encrypted_data': base64.b64encode(encrypted_data).decode()
        })
    
    def decrypt_data(self, crypted_data):
        '''Decrypts data generated by this class and returns it'''
        self._need_key()

        json_data = json.loads(crypted_data)
        if json_data['algorithm'] != 'AESGCM256':
            raise ValueError("Unknown Encryption!")
        
        initialization_vector = base64.b64decode(json_data['initialization_vector'])
        encrypted_data = base64.b64decode(json_data['encrypted_data'])

        aes_obj = AESGCM(base64.b64decode(self.key))
        decrypted_data = aes_obj.decrypt(
            initialization_vector,
            encrypted_data,
            None
        )

        return decrypted_data
