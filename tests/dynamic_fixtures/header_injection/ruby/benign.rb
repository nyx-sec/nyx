# Phase 08 (Track J.6) — Ruby HEADER_INJECTION benign control fixture.
#
# Same shape as `vuln.rb` but URL-encodes the value first via
# `URI.encode_www_form_component`, so CRLF bytes land as `%0D%0A` and
# the wire keeps a single header.
require 'rack'
require 'uri'

def run(value)
  response = Rack::Response.new
  response.set_header('Set-Cookie', URI.encode_www_form_component(value))
  response
end
