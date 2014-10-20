from IPy import IP, IPint
import requests
from requests.exceptions import RequestException
import stun


def init_additional_STUN_servers():
    """try calling this method only once"""
    # list of additional stun servers taken (and tested) from natvpn project
    # https://code.google.com/p/natvpn/source/browse/trunk/stun_server_list
    # removed those that didn't ping back.
    stun.stun_servers_list = stun.stun_servers_list + (
        'stun.l.google.com',
        'stun1.l.google.com',
        'stun2.l.google.com',
        'stun3.l.google.com',
        'stun4.l.google.com',
        'stun.ekiga.net',
        'stun.ideasip.com',
        'stun.iptel.org',
        'stun.schlund.de',
        'stunserver.org',
        'stun.voiparound.com',
        'stun.voipbuster.com',
        'stun.voipstunt.com',
        'stun.voxgratia.org',
        'stun.xten.com'
    )


def check_NAT_status():
    nat_type, external_ip, external_port = stun.get_ip_info()
    return {'nat_type': nat_type,
            'external_ip': external_ip,
            'external_port': external_port}


def is_loopback_addr(addr):
    return addr.startswith("127.0.0.") or addr == 'localhost'


def is_valid_port(port):
    return 0 < int(port) <= 65535


def is_valid_protocol(protocol):
    return protocol == 'tcp'


def is_private_ip_address(addr):
    return is_loopback_addr(addr) or IP(addr).iptype() != 'PUBLIC'


def get_my_ip():
    try:
        r = requests.get('https://icanhazip.com')
        return r.text.strip()
    except (AttributeError, RequestException) as e:
        print '[Requests] error: %s' % e
    return None


def is_ipv6_address(ip):
    address = IPint(ip)
    return address.version == 6


def get_peer_url(address, port, protocol='tcp'):
    """
    Returns a url for a peer that can be used by ZMQ

    @param address: A string which can be an IPv4 address, an IPv6 address
                    or a DNS name

    @param port: the port that will be used to connect to the peer
    """
    try:
        # is_ipv6_address will throw an exception for a DNS name
        is_ipv6 = is_ipv6_address(address)
    except ValueError:
        is_ipv6 = False

    if is_ipv6:
        # an IPv6 address must be enclosed in brackets
        return '%s://[%s]:%s' % (protocol, address, port)
    else:
        return '%s://%s:%s' % (protocol, address, port)
