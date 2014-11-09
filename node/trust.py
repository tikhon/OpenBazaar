import obelisk
import logging
import bitcoin
from twisted.internet import reactor

_log = logging.getLogger('trust')

TESTNET = False


def burnaddr_from_guid(guid_hex):
    _log.debug("burnaddr_from_guid: %s", guid_hex)

    if TESTNET:
        guid_hex = '6f' + guid_hex
    else:
        guid_hex = '00' + guid_hex

    _log.debug("GUID address on bitcoin net: %s", guid_hex)

    guid = guid_hex.decode('hex')

    _log.debug("Decoded GUID address on bitcoin net")

    # perturbate GUID
    # to ensure unspendability through
    # near-collision resistance of SHA256
    # by flipping the last non-checksum bit of the address

    guid = guid[:-1] + chr(ord(guid[-1]) ^ 1)

    _log.debug("Perturbated bitcoin proof-of-burn address")

    return obelisk.bitcoin.EncodeBase58Check(guid)


def get_global(guid, callback):
    get_unspent(burnaddr_from_guid(guid), callback)


def get_unspent(addr, callback):
    _log.debug('get_unspent call')

    def get_history():
        history = bitcoin.history(addr)
        total = 0

        for tx in history:
            total += tx['value']

        callback(total)

    reactor.callFromThread(get_history)
