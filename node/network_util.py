import IPy
import requests
import stun


# List taken and tested from natvpn project:
# https://code.google.com/p/natvpn/source/browse/trunk/stun_server_list
_ADDITIONAL_STUN_SERVERS = (
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


def set_stun_servers(servers=_ADDITIONAL_STUN_SERVERS):
    """Manually set the list of good STUN servers."""
    stun.stun_servers_list = tuple(servers)


def stun_servers_status_report(servers=_ADDITIONAL_STUN_SERVERS):
    good = []
    bad = []
    for s in servers:
        print "probing %s..." % s
        nt, ei, ep = stun.get_ip_info(stun_host=s, source_port=0)
        if ei is None and ep is None:
            print ":("
            bad.append(s)
        else:
            print ":)"
            good.append(s)

    if len(good) > 0:
        print "\n%s good servers\b" % len(good)
        for s in good:
            print " ", s

    if len(bad) > 0:
        print "\n%s bad servers" % len(bad)
        for s in bad:
            print " ", s


def get_NAT_status():
    nat_type, external_ip, external_port = stun.get_ip_info(source_port=0)

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
    return is_loopback_addr(addr) or IPy.IP(addr).iptype() != 'PUBLIC'


def get_my_ip():
    try:
        r = requests.get('https://icanhazip.com')
        return r.text.strip()
    except (AttributeError, requests.RequestException) as e:
        print '[Requests] error: %s' % e
    return None


def is_ipv6_address(ip):
    return IPy.IP(ip).version() == 6


def get_peer_url(address, port, protocol='tcp'):
    """
    Return a URL which can be used by ZMQ.

    @param address: An IPv4 address, an IPv6 address or a DNS name.
    @type address: str

    @param port: The port that will be used to connect to the peer
    @type port: int

    @param protocol: The connection protocol
    @type protocol: str

    @rtype: str
    """
    try:
        # is_ipv6_address will throw an exception for a DNS name
        is_ipv6 = is_ipv6_address(address)
    except ValueError:
        is_ipv6 = False

    if is_ipv6:
        # An IPv6 address must be enclosed in brackets.
        return '%s://[%s]:%s' % (protocol, address, port)
    else:
        return '%s://%s:%s' % (protocol, address, port)
