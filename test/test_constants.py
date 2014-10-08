import unittest

from node import constants


class TestConstants(unittest.TestCase):

    def test_exported_names(self):
        self.assertEqual(160, constants.BIT_NODE_ID_LEN)
        self.assertEqual(
            constants.BIT_NODE_ID_LEN // 4,
            constants.HEX_NODE_ID_LEN
        )
        self.assertEqual(80, constants.k)
        self.assertEqual(80, constants.cache_k)
        self.assertEqual(0.1, constants.rpcTimeout)
        self.assertEqual(86400, constants.dataExpireTimeout)
        self.assertEqual(60 * 60 * 1000, constants.refreshTimeout)
        self.assertEqual(
            constants.rpcTimeout / 2,
            constants.iterativeLookupDelay
        )
        self.assertEqual(constants.replicateInterval, constants.refreshTimeout)
        self.assertEqual(
            constants.refreshTimeout / 5,
            constants.checkRefreshInterval
        )
        self.assertEqual(8192, constants.udpDatagramMaxSize)
        self.assertEqual("db/ob.db", constants.DB_PATH)
        self.assertEqual("0.2.1", constants.VERSION)


if __name__ == "__main__":
    unittest.main()
