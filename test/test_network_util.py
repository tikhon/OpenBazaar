import unittest

from node import network_util


class TestNodeNetworkUtil(unittest.TestCase):
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
