# -*- coding: utf-8
import os
from datetime import datetime
import subprocess
import tempfile

from globaleaks.utils.crypto import AsyncCryptographyContext
from globaleaks.tests import helpers

from six import binary_type

class TestCryptographicServices(helpers.TestGL):
    def test_generate_key_pair(self):
        context = AsyncCryptographyContext()
        context.generate_private_key("test")

        self.assertTrue("ENCRYPTED PRIVATE KEY" in context.private_key_pem)
        self.pkcs8_decrypt(context.private_key_pem, "test")
        

    def test_change_password(self):
        context = AsyncCryptographyContext()
        context.generate_private_key("test")
        context.change_private_key_password("test2")
        with self.assertRaises(ValueError):
            self.pkcs8_decrypt(context.private_key_pem, "test")
        self.pkcs8_decrypt(context.private_key_pem, "test2")

    def test_create_self_signed_certificate(self):
        context = AsyncCryptographyContext()
        context.generate_private_key("test")
        context.generate_self_signed_certificate("Test Certificate")
        self.assertTrue("BEGIN CERTIFICATE" in context.certificate_pem)

    def test_encrypt_decrypt(self):
        context = AsyncCryptographyContext()
        context.generate_private_key("test")
        context.generate_self_signed_certificate("Test Certificate")
        enc_text = context.encrypt_data(b"test data")
        cleartext = context.decrypt_data(enc_text)
        self.assertEqual(cleartext, b"test data")

    def pkcs8_decrypt(self, priv_key_pem, passphrase):
        # Ensure that we can successfully read and decrypt the key with OpenSSL
        try:
            msg_fd, crypted_key = tempfile.mkstemp()
            os.write(msg_fd, binary_type(priv_key_pem, 'ascii'))
            os.close(msg_fd)
            msg_fd = 0
            openssl_cmd = ["openssl", "pkcs8", "-in", crypted_key, "-passin", "pass:" + passphrase]
            openssl_proc = subprocess.run(args=openssl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if openssl_proc.returncode != 0:
                raise ValueError("Unable to decrypt private key!")
        finally:
            os.remove(crypted_key)

