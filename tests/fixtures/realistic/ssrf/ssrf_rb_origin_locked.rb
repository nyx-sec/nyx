# Phase 14 fixture (Ruby negative) — `URI.join(base, path)` with a
# literal base anchors an origin-locked StringFact prefix that
# `is_string_safe_for_ssrf` honours, suppressing the SSRF sink at
# `Net::HTTP.get` even though the path component is attacker-controlled.
require 'net/http'
require 'uri'

class ProxyController
  def show
    path = params[:path]
    uri = URI.join("https://api.example.com/", path)
    Net::HTTP.get(uri)
  end
end
