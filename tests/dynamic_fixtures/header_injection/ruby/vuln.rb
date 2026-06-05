# Phase 08 (Track J.6) — Ruby HEADER_INJECTION vuln fixture.
#
# The function assigns the attacker-controlled `value` directly into a
# Rack response's `Set-Cookie` header via `Rack::Response#set_header`.
# A payload carrying `\r\nSet-Cookie: nyx-injected=pwn` splits the
# single header into two on the wire.
require 'rack'

def run(value)
  response = Rack::Response.new
  response.set_header('Set-Cookie', value)
  response
end
