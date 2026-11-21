# Phase 14 fixture (Ruby negative): `URI.join(base, path)` with a literal
# base and a path that starts with a fixed `v1/` segment.  The head makes the
# path a relative reference, which keeps the base host, so the origin-locked
# StringFact prefix suppresses the SSRF sink at `Net::HTTP.get` even though
# the tail of the path is attacker-controlled.  (A bare attacker path does not
# lock; see `ssrf_rb_uri_join_attacker_path.rb`.)
require 'net/http'
require 'uri'

class ProxyController
  def show
    path = params[:path]
    uri = URI.join("https://api.example.com/", "v1/" + path)
    Net::HTTP.get(uri)
  end
end
