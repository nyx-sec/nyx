# Phase 11 (Track J.9) — Ruby DATA_EXFIL benign control fixture.
require 'net/http'
require 'uri'

ALLOWLIST = %w[127.0.0.1 localhost].freeze

def run(host)
  return unless ALLOWLIST.include?(host)
  secret = "alice-creds"
  uri = URI("http://#{host}/exfil?token=#{secret}")
  Net::HTTP.get(uri)
end
