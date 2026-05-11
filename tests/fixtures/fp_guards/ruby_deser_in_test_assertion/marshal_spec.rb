# RSpec round-trip patterns: `expect(deser).to MATCHER`.  Same bounding
# semantics as the Minitest sibling fixture.

RSpec.describe MarshalRoundTrip do
  it "eq literal" do
    blob = Marshal.dump([1, 2, 3])
    expect(Marshal.load(blob)).to eq([1, 2, 3])
  end

  it "is nil" do
    blob = Marshal.dump(nil)
    expect(Marshal.load(blob)).to be_nil
  end

  it "is_a Array" do
    blob = Marshal.dump([1])
    expect(Marshal.load(blob)).to be_a(Array)
  end

  it "be_kind_of Array" do
    blob = Marshal.dump([1])
    expect(Marshal.load(blob)).to be_kind_of(Array)
  end

  it "be_truthy" do
    blob = Marshal.dump([1])
    expect(Marshal.load(blob)).to be_truthy
  end

  it "not_to be_nil" do
    blob = Marshal.dump([1])
    expect(Marshal.load(blob)).not_to be_nil
  end

  it "to_not be_nil" do
    blob = Marshal.dump([1])
    expect(Marshal.load(blob)).to_not be_nil
  end

  it "yaml load eq literal" do
    expect(YAML.load("- 1\n")).to eq([1])
  end

  it "match_array" do
    blob = Marshal.dump([1, 2, 3])
    expect(Marshal.load(blob)).to match_array([3, 2, 1])
  end
end
