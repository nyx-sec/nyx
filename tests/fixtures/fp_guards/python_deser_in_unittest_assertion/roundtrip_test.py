"""
unittest.TestCase methods that round-trip a value through pickle.dumps /
yaml.dump and assert the loads result equals a literal expected value.
Production Python projects ship hundreds of these in their test trees;
every firing is noise because the assertion bounds the deser result to
the literal expected.  Suppress `py.deser.pickle_loads`,
`py.deser.yaml_load`, `py.deser.shelve_open`, and the
`cfg-unguarded-sink` mirror on every shape below.
"""

import pickle
import yaml
import unittest


class RoundtripTest(unittest.TestCase):
    def test_dict_literal_expected(self):
        blob = pickle.dumps({"a": 1, "b": 2})
        self.assertEqual({"a": 1, "b": 2}, pickle.loads(blob))

    def test_list_literal_expected(self):
        blob = pickle.dumps([1, 2, 3])
        self.assertEqual([1, 2, 3], pickle.loads(blob))

    def test_nested_literal_expected(self):
        blob = pickle.dumps([{"k": "v"}, "tail"])
        self.assertEquals([{"k": "v"}, "tail"], pickle.loads(blob))

    def test_string_literal_expected(self):
        blob = pickle.dumps("hello")
        self.assertEqual("hello", pickle.loads(blob))

    def test_integer_literal_expected(self):
        blob = pickle.dumps(42)
        self.assertEqual(42, pickle.loads(blob))

    def test_unary_negative_expected(self):
        blob = pickle.dumps(-7)
        self.assertEqual(-7, pickle.loads(blob))

    def test_none_expected(self):
        blob = pickle.dumps(None)
        self.assertIsNone(pickle.loads(blob))

    def test_assert_true_bounds(self):
        blob = pickle.dumps(True)
        self.assertTrue(pickle.loads(blob))

    def test_assert_is_instance_dict(self):
        blob = pickle.dumps({"a": 1})
        self.assertIsInstance(pickle.loads(blob), dict)

    def test_assert_in_list(self):
        blob = pickle.dumps("apple")
        self.assertIn(pickle.loads(blob), ["apple", "banana"])

    def test_yaml_round_trip(self):
        blob = yaml.dump({"port": 5432})
        self.assertEqual({"port": 5432}, yaml.load(blob))

    def test_msg_kwarg_keeps_bound(self):
        blob = pickle.dumps([1])
        self.assertEqual([1], pickle.loads(blob), msg="round trip should preserve list")

    def test_actual_first_position(self):
        """pytest-style ordering: deser result first, literal second."""
        blob = pickle.dumps({"k": "v"})
        self.assertEqual(pickle.loads(blob), {"k": "v"})


# Free function imports also cover the suppression: `from pickle import loads`.
from pickle import loads as pickle_loads


class FreeImportTest(unittest.TestCase):
    def test_free_function_loads(self):
        blob = pickle.dumps([1, 2])
        self.assertEqual([1, 2], pickle_loads(blob))
