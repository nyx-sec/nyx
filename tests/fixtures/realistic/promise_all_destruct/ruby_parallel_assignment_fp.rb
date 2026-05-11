# Forcing-function fixture: Ruby `a, b = [tainted, literal]` parallel
# assignment with bare array-literal RHS must paint each binding from
# its source-order RHS slot.
#
# Engine timeline:
#   * Session 0044 added `left_assignment_list` to
#     `collect_array_pattern_bindings_indexed`, so both `a` and `b`
#     register as defs instead of the legacy `idents.pop()` path
#     silently dropping `a`.  Both bindings then carried the scalar
#     union of RHS uses (conservative correct, no FN).
#   * Per-index precision lift (this session): `TaintMeta` gained
#     `rhs_array_elements` recording per-slot RHS idents/literals.
#     `lower.rs` consumes this when LHS is a destructure pattern AND
#     RHS is a bare array literal — primary + extras emit per-slot
#     Assign (for idents) or Const(None) (for literals) instead of
#     cloning a union op.

require 'sinatra'
require 'net/http'

get '/u/:name' do |name|
  a, b = [name, "safe"]
  Net::HTTP.get(URI(a))   # Positive: a = name (tainted), MUST fire.
  Net::HTTP.get(URI(b))   # Negative: b = literal "safe", MUST NOT fire.
end

get '/v/:name' do |name|
  a, b = ["safe", name]
  Net::HTTP.get(URI(a))   # Negative: a = literal "safe", MUST NOT fire.
  Net::HTTP.get(URI(b))   # Positive: b = name (tainted), MUST fire.
end

get '/w/:name' do |name|
  a, b, c = [name, "x", "y"]
  Net::HTTP.get(URI(a))   # Positive: a = name (tainted), MUST fire.
  Net::HTTP.get(URI(b))   # Negative: b = literal "x", MUST NOT fire.
  Net::HTTP.get(URI(c))   # Negative: c = literal "y", MUST NOT fire.
end
