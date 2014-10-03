import unittest

from pybitcointools import main as arithmetic

from node import crypto_util


class TestCryptoUtil(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.privkey_hex = (
            'e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262'
        )
        cls.pubkey_hex = arithmetic.privkey_to_pubkey(cls.privkey_hex)
        cls.pubkey_hex_strip = cls.pubkey_hex[2:]

    def test_exported_names(self):
        self.assertEqual('secp256k1', crypto_util.BTC_CURVE)
        self.assertEqual('02ca', crypto_util.BTC_CURVE_OPENSSL_ID_HEX)
        self.assertEqual(32, crypto_util.BTC_EC_POINT_LENGTH)
        self.assertEqual('0020', crypto_util.BTC_EC_POINT_LENGTH_HEX)

    def test_pubkey_to_pyelliptic(self):
        pubkey_bin_fmt = crypto_util.pubkey_to_pyelliptic(self.pubkey_hex)

        point_len = crypto_util.BTC_EC_POINT_LENGTH
        header_bin = crypto_util.BTC_CURVE_OPENSSL_ID_HEX.decode('hex')
        length_bin = crypto_util.BTC_EC_POINT_LENGTH_HEX.decode('hex')
        pubkey_bin = arithmetic.changebase(
            self.pubkey_hex_strip, 16, 256, minlen=2*point_len
        )

        self.assertEqual(pubkey_bin_fmt[:2], header_bin)
        self.assertEqual(pubkey_bin_fmt[2:4], length_bin)
        self.assertEqual(pubkey_bin_fmt[4:4+point_len], pubkey_bin[:point_len])
        self.assertEqual(pubkey_bin_fmt[4+point_len:6+point_len], length_bin)
        self.assertEqual(pubkey_bin_fmt[6+point_len:], pubkey_bin[point_len:])

    def test_privkey_to_pyelliptic(self):
        privkey_bin_fmt = crypto_util.privkey_to_pyelliptic(self.privkey_hex)

        header_bin = crypto_util.BTC_CURVE_OPENSSL_ID_HEX.decode('hex')
        length_bin = crypto_util.BTC_EC_POINT_LENGTH_HEX.decode('hex')
        privkey_bin = arithmetic.changebase(
            self.privkey_hex, 16, 256, minlen=crypto_util.BTC_EC_POINT_LENGTH
        )

        self.assertEqual(privkey_bin_fmt[:2], header_bin)
        self.assertEqual(privkey_bin_fmt[2:4], length_bin)
        self.assertEqual(privkey_bin_fmt[4:], privkey_bin)


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
