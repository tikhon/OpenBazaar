import pyelliptic as ec
from bitcoin import main as arithmetic

BTC_CURVE = 'secp256k1'
BTC_CURVE_OPENSSL_ID_HEX = '{:0>4x}'.format(ec.OpenSSL.get_curve(BTC_CURVE))
BTC_EC_POINT_LENGTH = 32
BTC_EC_POINT_LENGTH_HEX = '{:0>4x}'.format(BTC_EC_POINT_LENGTH)


def pubkey_to_pyelliptic(pubkey_hex):
    """
    Convert a hex BTC public key into a format suitable for pyelliptic.

    @param pubkey_hex: Uncompressed BTC public key in hex format.
    @type pubkey_hex: str

    @return: A pyelliptic-compatible binary key.
    @rtype: str
    """
    # Strip the '04' prefix.
    pubkey_hex_strip = pubkey_hex[2:]

    # Add curve ID and key length.
    pubkey_hex_fmt = "".join((
        BTC_CURVE_OPENSSL_ID_HEX,
        BTC_EC_POINT_LENGTH_HEX, pubkey_hex_strip[:2 * BTC_EC_POINT_LENGTH],
        BTC_EC_POINT_LENGTH_HEX, pubkey_hex_strip[2 * BTC_EC_POINT_LENGTH:],
    ))

    # Convert to binary and return.
    len_key_bin = len(pubkey_hex_fmt) // 2
    return arithmetic.changebase(pubkey_hex_fmt, 16, 256, minlen=len_key_bin)


def privkey_to_pyelliptic(privkey_hex):
    """
    Convert a hex BTC private key into a format suitable for pyelliptic.

    @param privkey_hex: Compressed BTC private key in hex format.
    @type privkey_hex: str

    @return: A pyelliptic-compatible binary key.
    @rtype: str
    """
    # Add curve ID and key length.
    privkey_hex_fmt = "".join((
        BTC_CURVE_OPENSSL_ID_HEX,
        BTC_EC_POINT_LENGTH_HEX,
        privkey_hex
    ))

    # Convert to binary and return.
    len_key_bin = len(privkey_hex_fmt) // 2
    return arithmetic.changebase(privkey_hex_fmt, 16, 256, minlen=len_key_bin)


class Cryptor(object):
    """
    Enncapsulation of crypto services.
    """

    def __init__(self, pubkey_hex=None, privkey_hex=None):
        """
        Convert the keys and initialize the cryptor implementation.

        @param pubkey_hex: Uncompressed BTC public key in hex format.
        @type pubkey_hex: str

        @param privkey_hex: Compressed BTC private key in hex format.
        @type privkey_hex: str
        """
        if privkey_hex is None and pubkey_hex is None:
            raise ValueError("Neither public nor private key was specified.")

        if pubkey_hex is None:
            pubkey_hex = arithmetic.privkey_to_pubkey(privkey_hex)

        pubkey_bin = pubkey_to_pyelliptic(pubkey_hex)

        self.has_privkey = privkey_hex is not None
        if self.has_privkey:
            privkey_bin = privkey_to_pyelliptic(privkey_hex)
        else:
            privkey_bin = None

        self._ec = ec.ECC(
            curve=BTC_CURVE,
            pubkey=pubkey_bin,
            privkey=privkey_bin
        )

    def get_pubkey(self):
        """
        Return the public key in a format suitable for pyelliptic.

        @return: A pyelliptic-compatible binary public BTC key.
        @rtype: str
        """
        return self._ec.get_pubkey()

    def get_privkey(self):
        """
        Return the private key in a format suitable for pyelliptic.

        @return: A pyelliptic-compatible binary private BTC key or None
                 if absent.
        @rtype: str or NoneType
        """
        if self.has_privkey:
            return self._ec.get_privkey()
        return None

    def encrypt(self, data):
        """
        Encrypt a piece of data with own pubkey.

        @param data: The data to encrypt.
        @type data: str

        @return: The encrypted data.
        @rtype: str
        """
        return self._ec.encrypt(data, self._ec.get_pubkey())

    def decrypt(self, data):
        """
        Decrypt a piece of data encrypted with own pubkey.

        Intractable without the privkey.

        @param data: The data to decrypt.
        @type data: str

        @return: The decrypted data.
        @rtype: str

        @raise RuntimeError: Private key is absent or
                             MAC verification failed.
        @raise Exception: Decryption terminated abnormally.
        """
        if self.has_privkey:
            return self._ec.decrypt(data)
        raise RuntimeError("Cannot decrypt without private key.")

    def sign(self, data):
        """
        Sign a piece of data with own privkey.

        Intractable without the privkey.

        @param data: The data to sign.
        @type data: str

        @return: The signature on the data.
        @rtype: str

        @raise RuntimeError: Private key is absent.
        @raise Exception: Signing terminated abnormally.
        """
        if self.has_privkey:
            return self._ec.sign(data)
        raise RuntimeError("Cannot sign without private key.")

    def verify(self, sig, data):
        """
        Verify a piece of data signed with private key corresponsing
        to own pubkey.

        @param sig: The signature to verify.
        @type sig: str

        @param data: The data on which the signature was made.
        @type data: str

        @return: True if the signature is valid, False otherwise
        @rtype: bool

        @raise Exception: Verification terminated abnormally.
        """
        return self._ec.verify(sig, data)
