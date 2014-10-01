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
        self.assertTrue(hasattr(self.rt, 'log'))

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


class TestTreeRoutingTable(TestRoutingTable):
    """Test TreeRoutingTable implementation of RoutingTable."""

    @classmethod
    def setUpClass(cls):
        super(TestTreeRoutingTable, cls).setUpClass()

    def setUp(self):
        self.rt = routingtable.TreeRoutingTable(
            self.parent_node_id,
            self.market_id
        )

    def test_subclassing(self):
        self.assertIsInstance(self.rt, routingtable.RoutingTable)

    def test_init(self):
        super(TestTreeRoutingTable, self).test_init()

    def test_addContact(self):
        pass

    def test_findCloseNodes(self):
        pass

    def test_getContact(self):
        pass

    def test_getRefreshList(self):
        pass

    def test_removeContact(self):
        pass

    def test_touchKBucket(self):
        pass


class TestOptimizedTreeRoutingTable(TestTreeRoutingTable):
    """Test OptimizedTreeRoutingTable implementation of RoutingTable."""

    @classmethod
    def setUpClass(cls):
        super(TestOptimizedTreeRoutingTable, cls).setUpClass()

    def setUp(self):
        self.rt = routingtable.OptimizedTreeRoutingTable(
            self.parent_node_id,
            self.market_id
        )

    def test_subclassing(self):
        self.assertIsInstance(self.rt, routingtable.TreeRoutingTable)

    def test_init(self):
        super(TestOptimizedTreeRoutingTable, self).test_init()

if __name__ == "__main__":
    unittest.main()
