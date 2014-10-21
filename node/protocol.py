def shout(data):
    data['type'] = 'shout'
    return data


def proto_page(uri, pubkey, guid, text, signature, nickname, PGPPubKey, email,
               bitmessage, arbiter, notary, arbiter_description, sin):
    data = {
        'type': 'page',
        'uri': uri,
        'pubkey': pubkey,
        'senderGUID': guid,
        'text': text,
        'nickname': nickname,
        'PGPPubKey': PGPPubKey,
        'email': email,
        'bitmessage': bitmessage,
        'arbiter': arbiter,
        'notary': notary,
        'arbiter_description': arbiter_description,
        'sin': sin
    }
    return data


def query_page(guid):
    data = {'type': 'query_page', 'findGUID': guid}
    return data


def proto_store(key, value, originalPublisherID, age):
    data = {
        'type': 'store',
        'key': key,
        'value': value,
        'originalPublisherID': originalPublisherID,
        'age': age
    }
    return data


def negotiate_pubkey(nickname, ident_pubkey):
    data = {
        'type': 'negotiate_pubkey',
        'nickname': nickname,
        'ident_pubkey': ident_pubkey.encode("hex")
    }
    return data


def proto_response_pubkey(nickname, pubkey, signature):
    data = {
        'type': "proto_response_pubkey",
        'nickname': nickname,
        'pubkey': pubkey.encode("hex"),
        'signature': signature.encode("hex")
    }
    return data
