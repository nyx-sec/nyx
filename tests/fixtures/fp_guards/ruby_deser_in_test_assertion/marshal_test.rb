# Minitest round-trip patterns.  Each shape bounds the deserialized
# result to a literal expected; a poisoned blob produces a different
# shape, the assertion fails loudly, no object-injection side effect
# escapes the test boundary.  Layer C5 suppresses every finding here.

require "minitest/autorun"

class MarshalRoundTripTest < Minitest::Test
  def test_eq_array
    blob = Marshal.dump([1, 2, 3])
    assert_equal [1, 2, 3], Marshal.load(blob)
  end

  def test_eq_hash
    blob = Marshal.dump({a: 1})
    assert_equal({a: 1}, Marshal.load(blob))
  end

  def test_assert_nil
    blob = Marshal.dump(nil)
    assert_nil Marshal.load(blob)
  end

  def test_assert_truthy
    blob = Marshal.dump([1])
    assert Marshal.load(blob)
  end

  def test_kind_of
    blob = Marshal.dump([1])
    assert_kind_of Array, Marshal.load(blob)
  end

  def test_instance_of
    blob = Marshal.dump([1])
    assert_instance_of Array, Marshal.load(blob)
  end

  def test_refute_nil
    blob = Marshal.dump([1])
    refute_nil Marshal.load(blob)
  end

  def test_refute_equal_literal
    blob = Marshal.dump([1])
    refute_equal [9, 9], Marshal.load(blob)
  end

  def test_yaml_eq_literal
    assert_equal [1], YAML.load("- 1\n")
  end

  def test_assert_includes
    blob = Marshal.dump(2)
    assert_includes [1, 2, 3], Marshal.load(blob)
  end
end
