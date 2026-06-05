# Phase 09 (Track J.7) — Ruby OPEN_REDIRECT vuln fixture.
#
# The function splices `value` straight into
# `Rack::Response#redirect` without host validation; an attacker URL
# routes the captured `Location:` header off-origin.
require 'rack'

def run(value)
  response = Rack::Response.new
  response.redirect(value)
  response
end
