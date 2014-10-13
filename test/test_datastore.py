import unittest
import UserDict

import mock

from node import constants, datastore


class TestDataStore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = "a" * constants.HEX_NODE_ID_LEN

    def setUp(self):
        self.d = datastore.DataStore()

    def test_sublcassing(self):
        self.assertTrue(isinstance(self.d, UserDict.DictMixin))

    def test_init(self):
        # Already covered by the setUp.
        pass

    def test_keys(self):
        self.assertRaises(NotImplementedError, self.d.keys)

    def test_lastPublished(self):
        self.assertRaises(NotImplementedError, self.d.lastPublished, self.key)

    def test_originalPublisherID(self):
        self.assertRaises(
            NotImplementedError,
            self.d.originalPublisherID,
            self.key
        )

    def test_originalPublishTime(self):
        self.assertRaises(
            NotImplementedError,
            self.d.originalPublishTime,
            self.key
        )

    def test_setItem(self):
        pass


class TestSqliteDatastore(TestDataStore):

    def setUp(self):
        self.db_mock = mock.MagicMock()
        self.d = datastore.SqliteDataStore(self.db_mock)

    def test_init(self):
        super(TestSqliteDatastore, self).test_init()
        self.assertEqual(self.d.db, self.db_mock)

    def test_keys(self):
        pass

    def test_lastPublished(self):
        pass

    def test_originalPublisherID(self):
        pass

    def test_originalPublishTime(self):
        pass

    def test_setItem(self):
        pass
