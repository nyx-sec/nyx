# Phase 14 follow-up fixture (Ruby Faraday.new kwarg) — attacker-controlled
# base URL passed via the `url:` kwarg to `Faraday.new`. The constructor
# itself is the SSRF entry point: every subsequent verb call on the
# returned client (`client.get(path)`) inherits the tainted origin, so
# the Faraday SinkGate fires at construction time.
require 'faraday'

class ProxyController
  def show
    base = params[:base]
    client = Faraday.new(url: base)
    client.get('/status')
  end
end
