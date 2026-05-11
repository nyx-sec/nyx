"""pytest plain-`assert` round-trip patterns.  Each shape bounds the
deserialized result to a literal expected; a poisoned blob produces a
different shape, the assertion fails loudly, no object-injection side
effect escapes the test boundary.  Layer C4's pytest path suppresses
every finding here."""

import pickle
import yaml


def test_eq_literal():
    blob = pickle.dumps([1, 2, 3])
    assert pickle.loads(blob) == [1, 2, 3]


def test_neq_literal():
    blob = pickle.dumps([1])
    assert pickle.loads(blob) != [9, 9, 9]


def test_is_none():
    blob = pickle.dumps(None)
    assert pickle.loads(blob) is None


def test_is_not_none():
    blob = pickle.dumps([1])
    assert pickle.loads(blob) is not None


def test_in_literal_tuple():
    blob = pickle.dumps(2)
    assert pickle.loads(blob) in [1, 2, 3]


def test_not_in_literal():
    blob = pickle.dumps(99)
    assert pickle.loads(blob) not in [1, 2, 3]


def test_truthy_assertion():
    blob = pickle.dumps([1])
    assert pickle.loads(blob)


def test_not_truthy_assertion():
    blob = pickle.dumps(None)
    assert not pickle.loads(blob)


def test_isinstance_dict():
    blob = pickle.dumps({"a": 1})
    assert isinstance(pickle.loads(blob), dict)


def test_isinstance_tuple_of_types():
    blob = pickle.dumps([1])
    assert isinstance(pickle.loads(blob), (list, tuple))


def test_paren_wrap():
    blob = pickle.dumps([1])
    assert (pickle.loads(blob) == [1])


def test_assert_with_message():
    blob = pickle.dumps(1)
    assert pickle.loads(blob) == 1, "round trip failed"


def test_yaml_load_truthy():
    assert yaml.load(b"key: 1")


def test_bool_wrap():
    blob = pickle.dumps([1])
    assert bool(pickle.loads(blob))


def test_len_wrap():
    blob = pickle.dumps([1, 2, 3])
    assert len(pickle.loads(blob)) == 3


def test_unary_minus_eq_literal():
    blob = pickle.dumps(-7)
    assert -pickle.loads(blob) == 7
