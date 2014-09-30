import unittest

from node import constants, guid, routingtable


class TestRoutingTable(unittest.TestCase):
    """Test interface of abstract class RoutingTable."""

    @classmethod
    def setUpClass(cls):
        cls.parent_node_id = "abcdefghijklmnopqrst"
        cls.market_id = 42
        cls.guid = guid.GUIDMixin("YELLOW SUBMARINE")

    def setUp(self):
        self.rt = routingtable.RoutingTable(self.parent_node_id, self.market_id)

    def test_init(self):
        self.assertEqual(self.rt.parent_node_id, self.parent_node_id)
        self.assertEqual(self.rt.market_id, self.market_id)

    def test_addContact(self):
        self.assertRaises(
            NotImplementedError,
            self.rt.addContact,
            self.guid
        )

    def test_findCloseNodes(self):
        self.assertRaises(
            NotImplementedError,
            self.rt.findCloseNodes,
            self.id1,
            constants.k,
            rpc_node_id=self.id2
        )

    def test_getContact(self):
        self.assertRaises(
            NotImplementedError,
            self.rt.getContact,
            self.guid
        )

    def test_getRefreshList(self):
        self.assertRaises(
            NotImplementedError,
            self.rt.getRefreshList,
            start_index=1,
            force=True
        )

    def test_removeContact(self):
        self.assertRaises(
            NotImplementedError,
            self.rt.removeContact,
            self.guid
        )


if __name__ == "__main__":
    unittest.main()
