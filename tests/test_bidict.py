import operator
import unittest
from pyrad2.bidict import BiDict


class BiDictTests(unittest.TestCase):
    def setUp(self):
        self.bidict = BiDict()

    def test_start_empty(self):
        self.assertEqual(len(self.bidict), 0)
        self.assertEqual(len(self.bidict.forward), 0)
        self.assertEqual(len(self.bidict.backward), 0)

    def test_length(self):
        self.assertEqual(len(self.bidict), 0)
        self.bidict.add("from", "to")
        self.assertEqual(len(self.bidict), 1)
        del self.bidict["from"]
        self.assertEqual(len(self.bidict), 0)

    def test_deletion(self):
        self.assertRaises(KeyError, operator.delitem, self.bidict, "missing")
        self.bidict.add("missing", "present")
        del self.bidict["missing"]

    def test_backward_deletion(self):
        self.assertRaises(KeyError, operator.delitem, self.bidict, "missing")
        self.bidict.add("missing", "present")
        del self.bidict["present"]
        self.assertEqual(self.bidict.has_forward("missing"), False)

    def test_forward_access(self):
        self.bidict.add("shake", "vanilla")
        self.bidict.add("pie", "custard")
        self.assertEqual(self.bidict.has_forward("shake"), True)
        self.assertEqual(self.bidict.get_forward("shake"), "vanilla")
        self.assertEqual(self.bidict.has_forward("pie"), True)
        self.assertEqual(self.bidict.get_forward("pie"), "custard")
        self.assertEqual(self.bidict.has_forward("missing"), False)
        self.assertRaises(KeyError, self.bidict.get_forward, "missing")

    def test_backward_access(self):
        self.bidict.add("shake", "vanilla")
        self.bidict.add("pie", "custard")
        self.assertEqual(self.bidict.has_backward("vanilla"), True)
        self.assertEqual(self.bidict.get_backward("vanilla"), "shake")
        self.assertEqual(self.bidict.has_backward("missing"), False)
        self.assertRaises(KeyError, self.bidict.get_backward, "missing")

    def test_item_accessor(self):
        self.bidict.add("shake", "vanilla")
        self.bidict.add("pie", "custard")
        self.assertRaises(KeyError, operator.getitem, self.bidict, "missing")
        self.assertEqual(self.bidict["shake"], "vanilla")
        self.assertEqual(self.bidict["pie"], "custard")
