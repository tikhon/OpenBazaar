import unittest

import stun

from node import network_util


class TestNodeNetworkUtil(unittest.TestCase):

    def test_set_stun_servers(self):
        new_stun_servers = (
            'stun.openbazaar1.com',
            'stun.openbazaar2.com'
        )
        network_util.set_stun_servers(servers=new_stun_servers)
        self.assertItemsEqual(new_stun_servers, stun.stun_servers_list)

    def test_is_loopback_addr(self):
        self.assertTrue(network_util.is_loopback_addr("127.0.0.1"))
        self.assertTrue(network_util.is_loopback_addr("localhost"))

        self.assertFalse(network_util.is_loopback_addr("10.0.0.1"))
        self.assertFalse(network_util.is_loopback_addr("192.168.0.1"))

    def test_is_valid_port(self):
        self.assertTrue(network_util.is_valid_port(1))
        self.assertTrue(network_util.is_valid_port(2**16 - 1))

        self.assertFalse(network_util.is_valid_port(0))
        self.assertFalse(network_util.is_valid_port(2**16))

    def test_is_valid_protocol(self):
        self.assertTrue(network_util.is_valid_protocol('tcp'))

        self.assertFalse(network_util.is_valid_protocol('udp'))
        self.assertFalse(network_util.is_valid_protocol('baz'))

    def test_is_private_ip_address(self):
        self.assertTrue(network_util.is_private_ip_address('localhost'))
        self.assertTrue(network_util.is_private_ip_address('127.0.0.1'))
        self.assertTrue(network_util.is_private_ip_address('192.168.1.1'))
        self.assertTrue(network_util.is_private_ip_address('172.16.1.1'))
        self.assertTrue(network_util.is_private_ip_address('10.1.1.1'))

        self.assertFalse(network_util.is_private_ip_address('8.8.8.8'))

    def test_is_ipv6_address(self):
        self.assertTrue(network_util.is_ipv6_address('2a00::'))
        self.assertFalse(network_util.is_ipv6_address('8.8.8.8'))

    def test_get_peer_url(self):
        self.assertEqual(
            network_util.get_peer_url('8.8.8.8', 1234),
            'tcp://8.8.8.8:1234'
        )
        self.assertEqual(
            network_util.get_peer_url('8.8.8.8', 1234, protocol='udp'),
            'udp://8.8.8.8:1234'
        )
        self.assertEqual(
            network_util.get_peer_url('2a00::', 1234),
            'tcp://[2a00::]:1234'
        )
        self.assertEqual(
            network_util.get_peer_url('2a00::', 1234, protocol='udp'),
            'udp://[2a00::]:1234'
        )
        self.assertEqual(
            network_util.get_peer_url('www.openbazaar.com', 1234),
            'tcp://www.openbazaar.com:1234'
        )


if __name__ == '__main__':
    unittest.main()
