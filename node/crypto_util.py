import pyelliptic as ec
from pybitcointools import main as arithmetic

BTC_CURVE = 'secp256k1'
BTC_CURVE_OPENSSL_ID_HEX = '{:0>4x}'.format(ec.OpenSSL.get_curve(BTC_CURVE))
BTC_EC_POINT_LENGTH = 32
BTC_EC_POINT_LENGTH_HEX = '{:0>4x}'.format(BTC_EC_POINT_LENGTH)


def pubkey_to_pyelliptic(pubkey_hex):
    """
    Convert a hex BTC public key into a format suitable for pyelliptic.

    @param pubkey_hex: Uncompressed BTC public key in hex format.
    @type pubkey_hex: str or unicode

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
    @type privkey_hex: str or unicode

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


def makePrivCryptor(privkey_hex):
    """FILLME"""
    pubkey_hex = arithmetic.privkey_to_pubkey(privkey_hex)
    pubkey_bin = pubkey_to_pyelliptic(pubkey_hex)
    privkey_bin = privkey_to_pyelliptic(privkey_hex)
    return ec.ECC(curve=BTC_CURVE, privkey=privkey_bin, pubkey=pubkey_bin)


def makePubCryptor(pubkey_hex):
    """FILLME"""
    pubkey_bin = pubkey_to_pyelliptic(pubkey_hex)
    return ec.ECC(curve=BTC_CURVE, pubkey=pubkey_bin)
