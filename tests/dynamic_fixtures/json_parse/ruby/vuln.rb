# Phase 11 (Track J.9) — Ruby JSON_PARSE vuln fixture.
#
# JSON.parse the attacker bytes then recursively merge into a shared
# `OpenStruct`; the harness's instrumented `method_missing=` trap
# observes the `__nyx_canary` write.
require 'json'
require 'ostruct'

SHARED = OpenStruct.new

def run(value)
  parsed = JSON.parse(value)
  parsed.each { |k, v| SHARED[k] = v }
  SHARED
end
