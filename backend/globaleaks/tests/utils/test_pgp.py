# -*- coding: utf-8
import os
from datetime import datetime

from globaleaks.utils.pgp import PGPContext, PGPyContext
from globaleaks.tests import helpers

import pgpy

class TestPGP(helpers.TestGL):
    secret_content = helpers.PGPKEYS['VALID_PGP_KEY1_PRV']

    def test_encrypt_message(self):
        fake_receiver_desc = {
            'pgp_key_public': helpers.PGPKEYS['VALID_PGP_KEY1_PUB'],
            'pgp_key_fingerprint': u'BFB3C82D1B5F6A94BDAC55C6E70460ABF9A4C8C1',
            'username': u'fake@username.net',
        }

        pgpctx = PGPContext()
        pgpctx.load_key(helpers.PGPKEYS['VALID_PGP_KEY1_PRV'])

        encrypted_body = pgpctx.encrypt_message(fake_receiver_desc['pgp_key_fingerprint'],
                                                self.secret_content)

        self.assertEqual(str(pgpctx.gnupg.decrypt(encrypted_body)), self.secret_content)

    def test_encrypt_file(self):
        file_src = os.path.join(os.getcwd(), 'test_plaintext_file.txt')
        file_dst = os.path.join(os.getcwd(), 'test_encrypted_file.txt')

        fake_receiver_desc = {
            'pgp_key_public': helpers.PGPKEYS['VALID_PGP_KEY1_PRV'],
            'pgp_key_fingerprint': u'BFB3C82D1B5F6A94BDAC55C6E70460ABF9A4C8C1',
            'username': u'fake@username.net',
        }

        # these are the same lines used in delivery.py
        pgpctx = PGPContext()
        pgpctx.load_key(helpers.PGPKEYS['VALID_PGP_KEY1_PRV'])

        with open(file_src, 'wb+') as f:
            f.write(self.secret_content.encode())
            f.seek(0)

            pgpctx.encrypt_file(fake_receiver_desc['pgp_key_fingerprint'], f, file_dst)

        with open(file_dst, 'rb') as f:
            self.assertEqual(str(pgpctx.gnupg.decrypt_file(f)), self.secret_content)

    def test_read_expirations(self):
        pgpctx = PGPContext()

        self.assertEqual(pgpctx.load_key(helpers.PGPKEYS['VALID_PGP_KEY1_PRV'])['expiration'],
                         datetime.utcfromtimestamp(0))

        self.assertEqual(pgpctx.load_key(helpers.PGPKEYS['EXPIRED_PGP_KEY_PUB'])['expiration'],
                         datetime.utcfromtimestamp(1391012793))

class TestPGPy(helpers.TestGL):
    def test_key_generation(self):
        '''Test generating a PGP key'''
        pgpyctx = PGPyContext()
        pgpyctx.generate_key("GnuPG test user", "test@globaleaks.org", "12345678")
        self.assertNotEqual(pgpyctx.public_key, None)
        self.assertNotEqual(pgpyctx.private_key, None)

    def test_encrypt_decrypt(self):
        '''Test generating a PGP key'''
        pgpyctx = PGPyContext()
        pgpyctx.generate_key("GnuPG test user", "test@globaleaks.org", "12345678")
        enc_msg = pgpyctx.encrypt_text_message("Test message")
        decrypt_text = pgpyctx.decrypt_text_message(enc_msg, "12345678")

    def test_change_pw(self):
        '''Test generating a PGP key. Also tests from_blob'''
        pgpyctx1 = PGPyContext()
        pgpyctx1.generate_key("GnuPG test user", "test@globaleaks.org", "12345678")
        enc_msg = pgpyctx1.encrypt_text_message("Test message")

        pgpyctx1.change_passphrase("12345678", "87654321")

        pgpyctx2 = PGPyContext.from_blob(pgpyctx1.private_key)
        with self.assertRaises(pgpy.errors.PGPDecryptionError):
            pgpyctx2.decrypt_text_message(enc_msg, "12345678")
        decrypt_text = pgpyctx2.decrypt_text_message(enc_msg, "87654321")
        self.assertEqual(decrypt_text, "Test message")