import collections
import unittest

import stun

from node import network_util


class TestNodeNetworkUtil(unittest.TestCase):

    def test_init_additional_stun_servers(self):
        stun_servers_pre = stun.stun_servers_list
        new_stun_servers = (
            'stun.openbazaar1.com',
            'stun.openbazaar2.com'
        )
        network_util.init_additional_STUN_servers(servers=new_stun_servers)

        counter = collections.Counter(stun.stun_servers_list)

        # Check all new STUN servers are in.
        for server in new_stun_servers:
            self.assertEqual(counter[server], 1)

        network_util.init_additional_STUN_servers(servers=new_stun_servers)

        # Check no STUN server was removed or added twice.
        for server in stun_servers_pre:
            self.assertEqual(counter[server], 1)

    def test_is_loopback_addr(self):
        self.assertTrue(network_util.is_loopback_addr("127.0.0.1"))
        self.assertTrue(network_util.is_loopback_addr("localhost"))

        self.assertFalse(network_util.is_loopback_addr("10.0.0.1"))
        self.assertFalse(network_util.is_loopback_addr("192.168.0.1"))

    def test_is_valid_port(self):
        self.assertTrue(network_util.is_valid_port(1))
        self.assertTrue(network_util.is_valid_port(65335))

        self.assertFalse(network_util.is_valid_port(-1))
        self.assertFalse(network_util.is_valid_port(70000))

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


if __name__ == '__main__':
    unittest.main()
