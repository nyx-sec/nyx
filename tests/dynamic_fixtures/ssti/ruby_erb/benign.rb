# Phase 04 (Track J.2) — Ruby ERB benign control fixture.
#
# Escapes ERB markers in the body before rendering through a fixed
# template that interpolates only the sanitised value, so SSTI-shaped
# input cannot reach the evaluator.
require 'erb'

def run(body)
  safe_body = body.gsub(/<%/, '&lt;%').gsub(/%>/, '%&gt;')
  ERB.new('<%= safe_body %>').result(binding)
end
