import unittest

from pybitcointools import main as arithmetic

from node import crypto_util


class TestCryptoUtil(unittest.TestCase):

    def test_exported_names(self):
        self.assertEqual('secp256k1', crypto_util.BTC_CURVE)
        self.assertEqual('02ca', crypto_util.BTC_CURVE_OPENSSL_ID_HEX)
        self.assertEqual(32, crypto_util.BTC_EC_POINT_LENGTH)
        self.assertEqual('0020', crypto_util.BTC_EC_POINT_LENGTH_HEX)

    def test_pubkey_to_pyelliptic(self):
        pass

    def test_privkey_to_pyelliptic(self):
        pass


class TestPubCryptor(unittest.TestCase):

    def test_encrypt(self):
        pass

    def test_verify(self):
        pass

    def test_decrypt(self):
        # Test that attempt to decrypt will fail
        pass

    def test_sign(self):
        # Test that attempt to sign will fail
        pass


class TestPrivCryptor(TestPubCryptor):

    def test_decrypt(self):
        pass

    def test_sign(self):
        pass


if __name__ == "__main__":
    unittest.main()
