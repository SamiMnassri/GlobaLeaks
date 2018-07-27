# -*- coding: utf-8 -*-
import os
import shutil
import tempfile

from datetime import datetime

from gnupg import GPG

import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

from globaleaks.rest import errors
from globaleaks.utils.utility import log


class PGPContext(object):
    """
    PGP does not have a dedicated class, because one of the function is called inside a transact.
    I'm not confident creating an object that operates on the filesystem knowing that
    would be run also on the Storm cycle.
    """
    def __init__(self, tempdirprefix=None):
        """
        every time is needed, a new keyring is created here.
        """
        if tempdirprefix is None:
            tempdir = tempfile.mkdtemp()
        else:
            tempdir = tempfile.mkdtemp(prefix=tempdirprefix)

        try:
            gpgbinary='gpg'
            if os.path.exists('/usr/bin/gpg1'):
                gpgbinary='gpg1'

            self.gnupg = GPG(gpgbinary=gpgbinary, gnupghome=tempdir, options=['--trust-model', 'always'])
            self.gnupg.encoding = "UTF-8"
        except OSError as excep:
            log.err("Critical, OS error in operating with GnuPG home: %s", excep)
            raise
        except Exception as excep:
            log.err("Unable to instance PGP object: %s" % excep)
            raise

    def load_key(self, key):
        """
        @param key
        @return: a dict with the expiration date and the key fingerprint
        """
        try:
            import_result = self.gnupg.import_keys(key)
        except Exception as excep:
            log.err("Error in PGP import_keys: %s", excep)
            raise errors.InputValidationError

        if not import_result.fingerprints:
            raise errors.InputValidationError

        fingerprint = import_result.fingerprints[0]

        # looking if the key is effectively reachable
        try:
            all_keys = self.gnupg.list_keys()
        except Exception as excep:
            log.err("Error in PGP list_keys: %s", excep)
            raise errors.InputValidationError

        expiration = datetime.utcfromtimestamp(0)
        for k in all_keys:
            if k['fingerprint'] == fingerprint:
                if k['expires']:
                    expiration = datetime.utcfromtimestamp(int(k['expires']))
                break

        return {
            'fingerprint': fingerprint,
            'expiration': expiration
        }

    def encrypt_file(self, key_fingerprint, input_file, output_path):
        """
        Encrypt a file with the specified PGP key
        """
        encrypted_obj = self.gnupg.encrypt_file(input_file, str(key_fingerprint), output=output_path)

        if not encrypted_obj.ok:
            raise errors.InputValidationError

        return encrypted_obj,  os.stat(output_path).st_size

    def encrypt_message(self, key_fingerprint, plaintext):
        """
        Encrypt a text message with the specified key
        """
        encrypted_obj = self.gnupg.encrypt(plaintext, str(key_fingerprint))

        if not encrypted_obj.ok:
            raise errors.InputValidationError

        return str(encrypted_obj)

    def __del__(self):
        try:
            shutil.rmtree(self.gnupg.gnupghome)
        except Exception as excep:
            log.err("Unable to clean temporary PGP environment: %s: %s", self.gnupg.gnupghome, excep)

class PGPyContext(object):
    """
    For BrowserCrypto related events, we use pgpy for multiple reasons, specifically to
    allow us to not have to write keys out to disk, and to have better control of having
    things like private key encryption
    """

    def __init__(self):
        self.key_obj = None

    @property
    def public_key(self):
        if (self.key_obj) is None:
            raise errors.InputValidationError

        return str(self.key_obj.pubkey)

    @property
    def private_key(self):
        if (self.key_obj) is None:
            raise errors.InputValidationError

        return str(self.key_obj)

    def generate_key(self, name, email, passphrase):
        """
        @param name Real name to genreate on the key
        @param email Email address to use on the key
        """

        try:
            # Generate the primary key
            key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
            uid = pgpy.PGPUID.new(name, email=email)

            key.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA512, HashAlgorithm.SHA256],
                        ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.Camellia256],
                        compression=[CompressionAlgorithm.BZ2, CompressionAlgorithm.Uncompressed])

            # Generate the subkey
            subkey = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
            key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications})

            # Passwork protect
            key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

            self.key_obj = key

        except Exception as excep:
            log.err("Unable to generate PGP key: %s" % excep)
            raise

    def change_passphrase(self, old_passphrase, new_passphrase):
        """
        Changes the passphrase on the private key
        """

        with self.key_obj.unlock(old_passphrase) as ukey:
            ukey.protect(new_passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    def encrypt_text_message(self, plaintext):
        """
        Encrypt a text message with the specified key
        """

        msg_obj = pgpy.PGPMessage.new(plaintext)

        # Find the encrypt subkey
        pubkey = self.key_obj.pubkey
        encrypted_msg = self.key_obj.pubkey.encrypt(msg_obj)

        return str(encrypted_msg)

    def decrypt_text_message(self, crypttext, passphrase):
        """
        Decrypts a text message with specified key
        """
        msg_obj = pgpy.PGPMessage.from_blob(crypttext)
        with self.key_obj.unlock(passphrase) as ukey:
            return str(ukey.decrypt(msg_obj).message)
