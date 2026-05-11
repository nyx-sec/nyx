# Phase 14 fixture (Ruby search-params positive) — attacker-controlled
# URL passed to the module-level `Faraday.get(url)`. `Faraday.get` is
# a Phase 14 SSRF sink rule; the source-sensitivity gate keeps the
# finding active because `params[:target]` is plain user input.
require 'faraday'
require 'uri'

class ProxyController
  def show
    target = params[:target]
    Faraday.get(target, q: 'ok')
  end
end
