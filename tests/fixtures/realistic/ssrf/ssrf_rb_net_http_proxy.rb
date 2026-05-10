# Phase 14 follow-up fixture (Ruby Net::HTTP.start proxy_addr) — host is
# hardcoded but the proxy address is attacker-controlled, so the egress
# destination is still attacker-influenced. The Destination gate on the
# `proxy_addr:` kwarg fires even when the positional host is a literal.
require 'net/http'

class ProxyController
  def show
    proxy = params[:proxy]
    Net::HTTP.start('api.example.com', 443, proxy_addr: proxy) do |http|
      http.get('/status')
    end
  end
end
