# Forcing-function fixture: Ruby `a, b = [safe, tainted]` parallel
# assignment with bare array-literal RHS must propagate taint to BOTH
# bindings, not silently drop `a` via the legacy `idents.pop()` path
# that pre-fix kept only the LAST identifier as the assignment's def.
#
# Engine fix (session 0044):
#   * `collect_array_pattern_bindings_indexed` recognises
#     `left_assignment_list`.
#   * `def_use::Kind::Assignment` already runs the indexed helper, so
#     adding the Ruby kind into the outer match flows the parallel
#     bindings into `defs` + `extra_defines` automatically.
#
# Per-index precision (paint `a` from rhs[0] only, `b` from rhs[1]
# only) is NOT in scope here: the destructure-promise rewrite at
# src/ssa/lower.rs is gated on `is_any_promise_combinator(callee)`
# and Ruby has no canonical combinator call yet (no `Promise.all`
# analogue is recognised).  Both bindings receive the scalar union of
# RHS uses — conservative, correct, no FN.

require 'sinatra'
require 'net/http'

get '/u/:name' do |name|
  a, b = [name, "safe"]
  Net::HTTP.get(URI(a))   # Positive: tainted via union, MUST fire.
  Net::HTTP.get(URI(b))   # Positive: tainted via union, MUST fire.
end

get '/v/:name' do |name|
  a, b = ["safe", name]
  Net::HTTP.get(URI(a))   # Positive: tainted via union, MUST fire.
  Net::HTTP.get(URI(b))   # Positive: tainted via union, MUST fire.
end

get '/w/:name' do |name|
  a, b, c = [name, "x", "y"]
  Net::HTTP.get(URI(a))   # Positive: tainted via union, MUST fire.
  Net::HTTP.get(URI(b))   # Positive: tainted via union, MUST fire.
  Net::HTTP.get(URI(c))   # Positive: tainted via union, MUST fire.
end
