# Phase 04 (Track J.2) — Ruby ERB SSTI vuln fixture.
#
# The body is handed straight to ERB.new(...).result so an attacker
# who controls the body reaches the Ruby expression evaluator.
require 'erb'

def run(body)
  ERB.new(body).result
end
