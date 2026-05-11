# Phase 14 fixture (Ruby positive) — attacker-controlled URL flows
# directly into `Net::HTTP.get`.  The `params[:url]` source taints
# the URI, which reaches the `Net::HTTP.get` SSRF flat sink.
require 'net/http'
require 'uri'

class ProxyController
  def show
    target = params[:url]
    uri = URI.parse(target)
    Net::HTTP.get(uri)
  end
end
